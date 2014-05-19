/*
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

#include <kern/thread.h>
#include <libkern/libkern.h>
#include <mach-o/loader.h>
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <sys/malloc.h>
#include "capstone.h"
#include "cdisasm_utils.h"
#include "utlist.h"
#include "my_utils.h"

#define MAX_INSTRUCTIONS 8192
#define RF_FLAG_32BITS 0xFFFE8DFF
#define RF_FLAG_64BITS 0x0FFFFFFFFFFFE8DFF

extern struct kernel_info g_kernel_info; /* 'inficere.c' */

static kern_return_t disasm_jumps(mach_vm_address_t start, struct patch_location **patch_locations);

csh *init_capstone()
{
	csh *handle = _MALLOC(sizeof(csh), M_TEMP, M_WAITOK);
	
	if(handle == NULL) {
		return CS_ERR_MEM;
	}
	
	cs_opt_mem setup;
	
	/* setup our memory functions */
	setup.calloc = ifc_calloc;
	setup.free = ifc_free;
	setup.malloc = ifc_malloc;
	setup.realloc = ifc_realloc;
	setup.vsnprintf = vsnprintf;
	
	/* we use 0 as cs_handle *only* for setting up the memory management system - see capstone docs */
	if(cs_option(0, CS_OPT_MEM, &setup) != CS_ERR_OK) {
		goto fail;
	}
	
	int err = cs_open(CS_ARCH_X86, CS_MODE_64, handle);

	if(err != CS_ERR_OK) {
		goto fail;
	}
	
	err = cs_option(*handle, CS_OPT_DETAIL, CS_OPT_ON);
	
	if(err != CS_ERR_OK) {
		goto fail;
	}
	
	if(handle != NULL) {
		return handle;
	}

fail:
	if(handle != NULL)
		cs_close(handle);
	
	return NULL;
}

kern_return_t find_resume_flag(mach_vm_address_t start, struct patch_location **patch_locations)
{
	kern_return_t ret = KERN_FAILURE;
	
	csh *handle = init_capstone();
	
	if(handle == NULL) {
		goto fail;
	}
	
	unsigned long count = 0;
	cs_insn *insn;
	
	count = cs_disasm_ex(*handle, start, MAX_INSTRUCTIONS, start, 0, &insn);
	
	if(count == 0) {
		goto fail;
	}
	
	cs_insn ti;
	uint32_t i;
	
	struct jumps {
		mach_vm_address_t address;
		struct jumps *next;
	};
	
	struct jumps *jump_locations = NULL;
	
	for(i = 0; i < count; i++) {
		ti = insn[i];
		uint32_t imm32bit = ti.detail->x86.operands[1].imm & 0xFFFFFFFF;
		uint64_t imm64bit = ti.detail->x86.operands[1].imm;
		
		if(ti.id == X86_INS_AND && ti.detail->x86.operands[1].type == X86_OP_IMM && imm32bit == RF_FLAG_32BITS) {
			struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
			new->address = ti.address;
			new->size = ti.size;
			
			memcpy(new->orig_bytes, new->address, new->size);
			
			LL_PREPEND(*patch_locations, new);
		} else if(ti.id == X86_INS_MOV && ti.detail->x86.operands[1].type == X86_OP_IMM && imm64bit == RF_FLAG_64BITS) {
			struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
			new->address = ti.address;
			new->size = ti.size;
			
			memcpy(new->orig_bytes, new->address, new->size);
			
			LL_PREPEND(*patch_locations, new);
		} else if(ti.id == X86_INS_JMP && ti.detail->x86.operands[0].type == X86_OP_IMM) {
			mach_vm_address_t rip_addr = ti.detail->x86.operands[0].imm;
			struct jumps *new = _MALLOC(sizeof(struct jumps), M_TEMP, M_WAITOK);
			new->address = rip_addr;
			
			LL_PREPEND(jump_locations, new);
		}
	}
	
	struct jumps *jumps_tmp = NULL;
	
	LL_FOREACH(jump_locations, jumps_tmp) {
		disasm_jumps(jumps_tmp->address, patch_locations);
	}
	
	struct jumps *eljmp;
	struct jumps *tmpjmp;
	
	LL_FOREACH_SAFE(jump_locations, eljmp, tmpjmp) {
		_FREE(eljmp, M_TEMP);
	}
	
	cs_free(insn, count);
	
	ret = KERN_SUCCESS;
	
fail:
	if(handle != NULL)
		cs_close(handle);
	
	return ret;
}

kern_return_t find_task_for_pid(mach_vm_address_t start, struct patch_location *topatch)
{
	kern_return_t ret = KERN_FAILURE;
	
	csh *handle = init_capstone();
	
	if(handle == NULL) {
		goto fail;
	}
	
	unsigned long count = 0;
	cs_insn *insn;
	
	count = cs_disasm_ex(*handle, start, MAX_INSTRUCTIONS, start, 0, &insn);
	
	if(count == 0) {
		goto fail;
	}
	
	cs_insn ti;
	uint8_t target_reg = 0;
	int found_reg = 0;
	uint32_t i;
	
	for(i = 0; i < count; i++) {
		ti = insn[i];
		cs_x86_op *operands = ti.detail->x86.operands;
		
		if(ti.id == X86_INS_MOV && operands[1].type == X86_OP_MEM && operands[1].reg == X86_REG_RDI  && ti.detail->x86.disp == 0x8 && operands[0].type == X86_OP_REG) {
			target_reg = operands[0].reg;
			found_reg++;
		} else if(found_reg && ti.id == X86_INS_TEST && operands[0].type == X86_OP_REG && operands[0].reg == target_reg) {
			if(insn[i+1].id == X86_INS_JE) {
				topatch->jmp = 0;
				
				memcpy(topatch->orig_bytes, topatch->address, topatch->size);
			} else if(insn[i+1].id == X86_INS_JNE) {
				topatch->jmp = 1;
			} else {
				ret = KERN_FAILURE;
				
				goto out;
			}
			
			topatch->address = insn[i+1].address;
			topatch->size = insn[i+1].size;
			
			memcpy(topatch->orig_bytes, topatch->address, topatch->size);
			
			ret = KERN_SUCCESS;
			
			goto out;
		}
	}
	
out:
	cs_free(insn, count);
	
fail:
	if(handle != NULL)
		cs_close(handle);
	
	return ret;
}

kern_return_t find_kauth(mach_vm_address_t start, mach_vm_address_t sym_addr, struct patch_location *topatch)
{
	kern_return_t ret = KERN_FAILURE;
	
	csh *handle = init_capstone();
	
	if(handle == NULL) {
		goto fail;
	}
	
	unsigned long count = 0;
	cs_insn *insn;
	
	count = cs_disasm_ex(*handle, start, MAX_INSTRUCTIONS, start, 0, &insn);
	
	if(count == 0) {
		goto fail;
	}
	
	cs_insn ti;
	uint32_t i;
	
	for(i = 0; i < count; i++) {
		ti = insn[i];
		
		if(ti.id == X86_INS_CALL && ti.detail->x86.operands[0].type == X86_OP_IMM) {
			mach_vm_address_t rip_addr = ti.detail->x86.operands[0].imm;
			
			if(rip_addr == sym_addr) {
				uint32_t j;
				
				for(j = i; j < (i + 10) && j < count; j++) {
					ti = insn[j];
					
					if(ti.id == X86_INS_TEST) {
						uint32_t k;
						
						for(k = j; k < (j + 10) && k < count; k++) {
							ti = insn[k];
							
							if(ti.id == X86_INS_JNE) {
								topatch->address = ti.address;
								topatch->size = ti.size;
								
								memcpy(topatch->orig_bytes, topatch->address, topatch->size);
								
								topatch->jmp = 1;
								
								ret = KERN_SUCCESS;
								
								goto out;
							}
						}
					}
				}
			}
		}
	}

out:
	cs_free(insn, count);
	
fail:
	if(handle != NULL)
		cs_close(handle);
	
	return ret;
}

static kern_return_t disasm_jumps(mach_vm_address_t start, struct patch_location **patch_locations)
{
	kern_return_t ret = KERN_FAILURE;
	
	csh *handle = init_capstone();
	
	if(handle == NULL) {
		goto fail;
	}
	
	unsigned long count = 0;
	cs_insn *insn;
	
	count = cs_disasm_ex(*handle, start, MAX_INSTRUCTIONS, start, 0, &insn);
	
	if(count == 0) {
		goto fail;
	}
	
	cs_insn ti;
	uint32_t i;
	
	for(i = 0; i < count; i++) {
		ti = insn[i];
		uint32_t imm32bit = ti.detail->x86.operands[1].imm & 0xFFFFFFFF;
		uint64_t imm64bit = ti.detail->x86.operands[1].imm;
		
		if(ti.id == X86_INS_AND && ti.detail->x86.operands[1].type == X86_OP_IMM && imm32bit == RF_FLAG_32BITS) {
			struct patch_location *tmp = NULL;
			int exists = 0;
			LL_FOREACH(*patch_locations, tmp) {
				if(tmp->address == ti.address) {
					exists++;
				}
			}
			
			if(exists == 0) {
				struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
				new->address = ti.address;
				new->size = ti.size;
				
				memcpy(new->orig_bytes, new->address, new->size);
				
				LL_PREPEND(*patch_locations, new);
				
			}
		} else if(ti.id == X86_INS_MOV && ti.detail->x86.operands[1].type == X86_OP_IMM && imm64bit == RF_FLAG_64BITS) {
			struct patch_location *tmp = NULL;
			int exists = 0;
			
			LL_FOREACH(*patch_locations, tmp) {
				if(tmp->address == ti.address) {
					exists++;
				}
			}
			
			if(exists == 0) {
				struct patch_location *new = _MALLOC(sizeof(struct patch_location), M_TEMP, M_WAITOK);
				new->address = ti.address;
				new->size = ti.size;
				
				memcpy(new->orig_bytes, new->address, new->size);
				
				LL_PREPEND(*patch_locations, new);
				
			}
		}
	}
	
	cs_free(insn, count);
	
	ret = KERN_SUCCESS;
	
fail:
	if(handle != NULL)
		cs_close(handle);
	
	return ret;
}