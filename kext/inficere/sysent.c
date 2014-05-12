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

#include "sysent.h"
#include "cpu_protections.h"
#include "data_def.h"
#include "idt.h"

struct sysent *g_sysent;

/*
 *	16 bytes IDT descriptor, used for 32- and 64-bit kernels (64-bit capable CPUs)
 */
struct descriptor_idt {
	uint16_t offset_low;
	uint16_t seg_selector;
	uint8_t reserved;
	uint8_t flag;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved2;
};

static int process_header(const mach_vm_address_t target_addr, uint64_t *data_addr, uint64_t *data_size);
static void *bruteforce_sysent(void);

/*
 *	Externally available functions to find sysent table
 *	If it fails, kext should not load
 */
kern_return_t find_sysent(void)
{
	/* get sysent address */
	g_sysent = (struct sysent *)bruteforce_sysent();
	
	if(g_sysent == NULL) {
		return KERN_FAILURE;
	}
	
	return KERN_SUCCESS;
}

/*
 *	Calculate the address of the kernel int80 handler using the IDT array
 */
mach_vm_address_t calc_int80_addr(const mach_vm_address_t idt_addr)
{
	/*
	 * find the address of the interrupt 0x80 - EXECP64_SPC_USR(0x80, hi64_unix_scall)
	 *
	 * from osfmk/i386/idt64.s
	 */
	struct descriptor_idt *int80_desc;
	mach_vm_address_t int80_addr;
	
	/* it's necessary to calculate the address, not just directly extract the stub address */
#if __LP64__
	/* get the descriptor for interrupt 0x80 */
	/* IDT == array of descriptors */
	int80_desc = (struct descriptor_idt *)(idt_addr + sizeof(struct descriptor_idt) * 0x80);
	uint64_t high = (unsigned long)int80_desc->offset_high << 32;
	uint32_t middle = (unsigned long)int80_desc->offset_middle << 16;
	int80_addr = (mach_vm_address_t)(high + middle + int80_desc->offset_low);
#else
	int80_desc = (struct descriptor_idt *)(idt_addr + sizeof(struct descriptor_idt)*0x80);
	int80_addr = (mach_vm_address_t)(int80_desc->offset_middle << 16) + int80_desc->offset_low;
#endif

	return int80_addr;
}

/*
 *	Find the kernel base address (Mach-O header) by searching backwards using the int80 handler
 *	as a starting point
 */
mach_vm_address_t find_kbase(const mach_vm_address_t int80_addr)
{
	mach_vm_address_t tmp_addr = int80_addr;
	
#if __LP64__
	struct segment_command_64 *seg_cmd = NULL;
	
	while(tmp_addr > 0) {
		if(*(uint32_t *)(tmp_addr) == MH_MAGIC_64) {
			/* make sure it's the header and not some reference to the MAGIC number */
			seg_cmd = (struct segment_command_64 *)(tmp_addr + sizeof(struct mach_header_64));
			
			if(strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
				return tmp_addr;
			}
		}
		
		if(tmp_addr -1 > tmp_addr)
			break;
		
		tmp_addr--;
	}
#else
	struct segment_command *seg_cmd = NULL;
	
	while(tmp_addr > 0) {
		if(*(uint32_t *)((uint32_t)tmp_addr) == MH_MAGIC) {
			/* make sure it's the header and not some reference to the MAGIC number */
			seg_cmd = (struct segment_command *)((uint32_t)tmp_addr + sizeof(struct mach_header));
			
			if(strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
				return (mach_vm_address_t)tmp_addr;
			}
		}
		
		if(tmp_addr - 1 > tmp_addr)
			break;
		
		tmp_addr--;
	}
#endif
	
	return 0;
}

/*
 *	32/64bit compatible brute force method to find sysent
 *	Works in all versions
 *	Returns a pointer to the sysent structure
 */
static void *bruteforce_sysent(void)
{
	/* get IDT address */
	mach_vm_address_t idt_addr = 0;
	get_idt_addr(&idt_addr);
	
	/* calculate the address of the int80 handler */
	mach_vm_address_t int80_addr = calc_int80_addr(idt_addr);
	
	/* search backwards for the kernel base address (mach-o header) */
	mach_vm_address_t kbase = find_kbase(int80_addr);
	uint64_t data_addr = 0;
	uint64_t data_size = 0;
	
	/* search for the __DATA segment */
	process_header(kbase, &data_addr, &data_size);
	uint64_t data_limit = data_addr + data_size;
	
	/* bruteforce search for sysent in __DATA segment */
	while(data_addr <= data_limit) {
		struct sysent *table = (struct sysent *)data_addr;
		
		if((void *)table != NULL &&
		   table[SYS_exit].sy_narg      == 1 &&
		   table[SYS_fork].sy_narg      == 0 &&
		   table[SYS_read].sy_narg      == 3 &&
		   table[SYS_wait4].sy_narg     == 4 &&
		   table[SYS_ptrace].sy_narg    == 4 &&
		   table[SYS_getxattr].sy_narg  == 6 &&
		   table[SYS_listxattr].sy_narg == 4 &&
		   table[SYS_recvmsg].sy_narg   == 3)
		{
			return table;
		}
		
		data_addr++;
	}
	
	return NULL;
}

/*
 *	Process target kernel module header and get some info we need, more specifically the __DATA segment
 */
static int process_header(const mach_vm_address_t target_addr, uint64_t *data_addr, uint64_t *data_size)
{
	/* verify if it's a valid mach-o binary */
	struct mach_header *mh = (struct mach_header *)target_addr;
	
	if(mh == NULL) {
		/* error */
		return 1;
	}
	
	size_t header_size = 0;
	
	if(mh->magic == MH_MAGIC) {
		header_size = sizeof(struct mach_header);
	} else if(mh->magic == MH_MAGIC_64) {
		header_size = sizeof(struct mach_header_64);
	} else {
		/* error */
		return 1;
	}
	
	/* find the last command offset */
	struct load_command *load_cmd = NULL;
	char *load_cmd_addr = (char *)target_addr + header_size;
	
	for(uint32_t i = 0; i < mh->ncmds; i++) {
		load_cmd = (struct load_command *)load_cmd_addr;
		
		switch(load_cmd->cmd) {
			case LC_SEGMENT:
			{
				struct segment_command *seg_cmd = (struct segment_command *)load_cmd;
				
				if(strncmp(seg_cmd->segname, "__DATA", 16) == 0) {
					*data_addr = seg_cmd->vmaddr;
					*data_size = seg_cmd->vmsize;
					
				}
				
				break;
			}
				
			case LC_SEGMENT_64:
			{
				struct segment_command_64 *seg_cmd = (struct segment_command_64 *)load_cmd;
				
				if(strncmp(seg_cmd->segname, "__DATA", 16) == 0) {
					*data_addr = seg_cmd->vmaddr;
					*data_size = seg_cmd->vmsize;
					
				}
				
				break;
			}
				
			default:
				break;
		}
		
		/* advance to next command */
		load_cmd_addr += load_cmd->cmdsize;
	}
	
	return 0;
}