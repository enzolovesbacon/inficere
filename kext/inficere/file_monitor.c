/*
 *
 
 Copyright (c) 2007 by Apple Computer, Inc., All Rights Reserved.
 
 Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple Computer, Inc.
                         ("Apple") in consideration of your agreement to the following terms, and your
 use, installation, modification or redistribution of this Apple software
 constitutes acceptance of these terms.  If you do not agree with these terms,
 please do not use, install, modify or redistribute this Apple software.
 
 In consideration of your agreement to abide by the following terms, and subject
 to these terms, Apple grants you a personal, non-exclusive license, under Apple's
 copyrights in this original Apple software (the "Apple Software"), to use,
 reproduce, modify and redistribute the Apple Software, with or without
 modifications, in source and/or binary forms; provided that if you redistribute
 the Apple Software in its entirety and without modifications, you must retain
 this notice and the following text and disclaimers in all such redistributions of
 the Apple Software.  Neither the name, trademarks, service marks or logos of
 Apple Computer, Inc. may be used to endorse or promote products derived from the
 Apple Software without specific prior written permission from Apple.  Except as
 expressly stated in this notice, no other rights or licenses, express or implied,
 are granted by Apple herein, including but not limited to any patent rights that
 may be infringed by your derivative works or by other works in which the Apple
 Software may be incorporated.
 
 The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
 COMBINATION WITH YOUR PRODUCTS.
 
 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
 OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
 (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 *
 *
 * https://developer.apple.com/library/mac/technotes/tn2127/_index.html
 *
 */

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/param.h>
#include "data_def.h"
#include "file_monitor.h"
#include "anti.h"

#define VNODE_ACTION(action)                        { KAUTH_VNODE_ ## action, #action, NULL }
#define VNODE_ACTION_FILEDIR(actionFile, actionDir) { KAUTH_VNODE_ ## actionFile, #actionFile, #actionDir }

static signed int g_activation_count = 0;
static char g_config[] = "add com.apple.kauth.fileop";
static const char *g_prefix = NULL;
static char *g_listener_scope = NULL;
static kauth_listener_t g_listener = NULL;

#pragma mark vnode utils

struct vnodeActionInfo {
	/*
	 * pulled out of vnode_scope_listener
	 *
	 * this describes one of the action bits in the vnode scope's action field
	 */
	kauth_action_t      fMask;                   /* only one bit should be set */
	const char          *fOpNameFile;            /* descriptive name of the bit for files */
	const char          *fOpNameDir;             /* descriptive name of the bit for directories */
};

typedef struct vnodeActionInfo vnodeActionInfo_t;

/*
 *	This is a table of all the known action bits and their human readable names
 */
static const vnodeActionInfo_t kVnodeActionInfo[] = {
	VNODE_ACTION_FILEDIR(READ_DATA, LIST_DIRECTORY),
	VNODE_ACTION_FILEDIR(WRITE_DATA,ADD_FILE),
	VNODE_ACTION_FILEDIR(EXECUTE, SEARCH),
	VNODE_ACTION(DELETE),
	VNODE_ACTION_FILEDIR(APPEND_DATA, ADD_SUBDIRECTORY),
	VNODE_ACTION(DELETE_CHILD),
	VNODE_ACTION(READ_ATTRIBUTES),
	VNODE_ACTION(WRITE_ATTRIBUTES),
	VNODE_ACTION(READ_EXTATTRIBUTES),
	VNODE_ACTION(WRITE_EXTATTRIBUTES),
	VNODE_ACTION(READ_SECURITY),
	VNODE_ACTION(WRITE_SECURITY),
	VNODE_ACTION(TAKE_OWNERSHIP),
	VNODE_ACTION(SYNCHRONIZE),
	VNODE_ACTION(LINKTARGET),
	VNODE_ACTION(CHECKIMMUTABLE),
	VNODE_ACTION(ACCESS),
	VNODE_ACTION(NOIMMUTABLE)
};

#define kVnodeActionInfoCount	(sizeof(kVnodeActionInfo) / sizeof(*kVnodeActionInfo))

/*
 *	Creates a human readable description of a vnode action bitmap
 */
static int create_vnode_action_str(kauth_action_t action, boolean_t isDir, char **actionstrp, size_t *actionstr_lenp)
{
	enum { kCalcLen, kCreateString } pass;
	kauth_action_t actions_left;
	unsigned int info_idx;
	size_t actionstr_len;
	char *actionstr;
	
	actionstr = NULL;
	
	/*
	 * on first pass, actionstr is null and we calculate actionstr_len, at the end we allocate actionstr
	 * on second pass, actionstr is initialised
	 */
	for(pass = kCalcLen; pass <= kCreateString; pass++) {
		actions_left = action;
		
		/* process action bits that are described in kVnodeActionInfo. */
		info_idx = 0;
		actionstr_len = 0;
		
		while((actions_left != 0) && (info_idx < kVnodeActionInfoCount)) {
			if(actions_left & kVnodeActionInfo[info_idx].fMask) {
				const char *cur_str;
				size_t cur_str_len;
				
				/* increment the length of actionstr by the action name */
				
				if(isDir && (kVnodeActionInfo[info_idx].fOpNameDir != NULL)) {
					cur_str = kVnodeActionInfo[info_idx].fOpNameDir;
				} else {
					cur_str = kVnodeActionInfo[info_idx].fOpNameFile;
				}
				cur_str_len = strlen(cur_str);
				
				if(actionstr != NULL) {
					memcpy(&actionstr[actionstr_len], cur_str, cur_str_len);
				}
				
				actionstr_len += cur_str_len;
				
				/* clear the bit in actions_left, indicating that we processed this one */
				actions_left &= ~kVnodeActionInfo[info_idx].fMask;
				
				/* if there is any actions left, append it prefixing '|' */
				if(actions_left != 0) {
					if(actionstr != NULL) {
						actionstr[actionstr_len] = '|';
					}
					
					actionstr_len += 1;
				}
			}
			
			info_idx += 1;
		}
		
		/* now we include any remaining actions as a hex number */
		if(actions_left != 0) {
			if(actionstr != NULL) {
				/* 11 == '0' + 'x' + 8 digits + null char */
				snprintf(&actionstr[actionstr_len], 11, "0x%08x", actions_left);
			}
			
			actionstr_len += 10; /* 0x + 8 hex digits */
		}
		
		/*
		 * if we're at the end of the first pass, allocate actionstr based on the size we just calculated
		 * actionstr_len is a string length, so we have to allocate an extra character for the null terminator
		 * if we're at the end of the second pass, just place the null terminator
		 */
		if(pass == kCalcLen) {
			actionstr = _MALLOC(actionstr_len + 1, M_TEMP, M_WAITOK);
			
			if(actionstr == NULL) {
				return ENOMEM;
			}
		} else {
			actionstr[actionstr_len] = 0;
		}
	}
	
	/* clean up */
	*actionstrp = actionstr;
	*actionstr_lenp = actionstr_len + 1;
	
	return 0;
}

/*
 *	Creates a full path for a vnode.
 *
 *	Callers are responsible for freeing vp_p (size is always MAXPATHLEN)
 */
static int create_vnode_path(vnode_t vp, char **vp_p)
{
	int pathlen;
	
	if(vp != NULL) {
		*vp_p = _MALLOC(MAXPATHLEN, M_TEMP, M_WAITOK);

		if(*vp_p == NULL) {
			return ENOMEM;
		}
		
		pathlen = MAXPATHLEN;
		
		return vn_getpath(vp, *vp_p, &pathlen);
	}
	
	return EINVAL;
}

/*
 *	A kauth listener that's called to authorize an action in the generic scope (KAUTH_SCOPE_GENERIC)
 *
 *	For now, we just dump the parameters to the operation and return KAUTH_RESULT_DEFER, allowing other listeners to decide it's allowed or not
 *
 *	See the artile on the top of this file for a detailed explanation of 'arg0' through 'arg3'
 */
static int scope_listener(kauth_cred_t cred, void *data, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	OSIncrementAtomic(&g_activation_count);
	
	switch(action) {
		case KAUTH_GENERIC_ISSUSER:
			//LOG_DEBUG("scope=" KAUTH_SCOPE_GENERIC ", action=KAUTH_GENERIC_ISSUSER, actor=%ld\n", (long)kauth_cred_getuid(cred) );
			
			break;
			
		default:
			//LOG_DEBUG("[ERROR] scope_listener: Unknown action (%d)\n", action);
			
			break;
	}
	
	OSDecrementAtomic(&g_activation_count);
	
	return KAUTH_RESULT_DEFER;
}

/*
 *	A kauth listener that's called to authorize an action in the process scope (KAUTH_SCOPE_PROCESS)
 *
 *	For now, we just dump the parameters to the operation and return KAUTH_RESULT_DEFER, allowing other listeners to decide it's allowed or not
 *
 *	See the artile on the top of this file for a detailed explanation of 'arg0' through 'arg3'
 */
static int process_scope_listener(kauth_cred_t cred, void *data, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	OSIncrementAtomic(&g_activation_count);
	
	switch(action) {
		case KAUTH_PROCESS_CANSIGNAL:
			break;
		case KAUTH_PROCESS_CANTRACE:
			break;
		default:
			break;
	}
	
	OSDecrementAtomic(&g_activation_count);
	
	return KAUTH_RESULT_DEFER;
}

/*
 *	A kauth listener that's called to authorize an action in the vnode scope (KAUTH_SCOPE_VNODE)
 *
 *	See the artile on the top of this file for a detailed explanation of 'arg0' through 'arg3'
 */
static int vnode_scope_listener(kauth_cred_t cred, void *data, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	vfs_context_t context;
	vnode_t vp;
	vnode_t dvp;
	char *vp_path;
	char *dvp_path;
	boolean_t isDir;
	char *actionstr;
	size_t actionstr_len = 0;
	
	OSIncrementAtomic(&g_activation_count);
	
	context = (vfs_context_t)arg0;
	vp = (vnode_t)arg1;
	dvp = (vnode_t)arg2;
	
	vp_path = NULL;
	dvp_path = NULL;
	actionstr = NULL;
	
	if(create_vnode_path(vp, &vp_path) != 0)
		goto fail;
	
	if(create_vnode_path(dvp, &dvp_path) != 0)
		goto fail;
	
	if(vp != NULL) {
		isDir = (vnode_vtype(vp) == VDIR);
	} else {
		isDir = FALSE;
	}
	
	if(create_vnode_action_str(action, isDir, &actionstr, &actionstr_len) != 0) {
		goto fail;
	}
		
	/* requests are filtered based on g_prefix */
	if((g_prefix == NULL) || (((vp_path != NULL) && strprefix(vp_path, g_prefix)) || ((dvp_path != NULL) && strprefix(dvp_path, g_prefix)))) {
		/*
		 *
		 */
	}

fail:
	/* clean up */
	if(actionstr != NULL) {
		_FREE(actionstr, M_TEMP);
	}
	
	if(vp_path != NULL) {
		_FREE(vp_path, M_TEMP);
	}
	
	if(dvp_path != NULL) {
		_FREE(dvp_path, M_TEMP);
	}
	
	OSDecrementAtomic(&g_activation_count);
	
	return KAUTH_RESULT_DEFER;
}

/*
 *	A kauth listener that's called to authorize an action in the file operation scope (KAUTH_SCOPE_FILEOP)
 *
 *	See the artile on the top of this file for a detailed explanation of 'arg0' through 'arg3'
 */
static int fileop_scope_listener(kauth_cred_t cred, void *data, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	OSIncrementAtomic(&g_activation_count);
	
	const char *pathstr = (const char *)arg1;
	
	switch(action) {
		case KAUTH_FILEOP_OPEN:
			if((g_prefix == NULL) || strprefix((const char *)arg1, g_prefix)) {
				if(strncmp(pathstr, "/var/run/utmpx", strlen("/var/run/utmpx")) == 0) {
					/*
					 *	TODO: Find something interesting to do here. My original idea didn't work.
					 */
				}
			}
			
			break;
			
		case KAUTH_FILEOP_CLOSE:
			if((g_prefix == NULL) || strprefix((const char *)arg1, g_prefix)) {
				if(strncmp(pathstr, MACH_KERNEL, strlen(MACH_KERNEL)) == 0) {
					/*
					 *	TODO: Find something interesting to do here. My original idea didn't work.
					 */
				}
			}
			
			break;
		
		/*
		 *	XXX: Not used
		 *
		case KAUTH_FILEOP_RENAME:
			if((arg0 == 0) || (arg1 == 0)) {
				LOG_DEBUG("KAUTH_FILEOP_RENAME");
			} else {
				if((g_prefix == NULL) || (strprefix((const char *)arg0, g_prefix) || strprefix((const char *)arg1, g_prefix))) {
					//LOG_DEBUG("scope=" KAUTH_SCOPE_FILEOP ", action=KAUTH_FILEOP_RENAME, uid=%ld, from=%s, to=%s\n", (long)kauth_cred_getuid(cred), (const char *)arg0, (const char *)arg1);
				}
			}
			
			break;
			
		case KAUTH_FILEOP_EXCHANGE:
			if((arg0 == 0) || (arg1 == 0)) {
				LOG_DEBUG("KAUTH_FILEOP_EXCHANGE");
			} else {
				if((g_prefix == NULL) || (strprefix((const char *)arg0, g_prefix) || strprefix((const char *)arg1, g_prefix))) {
					LOG_DEBUG("scope=" KAUTH_SCOPE_FILEOP ", action=KAUTH_FILEOP_EXCHANGE, uid=%ld, file1=%s, file2=%s\n", (long)kauth_cred_getuid(cred), (const char *)arg0, (const char *)arg1);
				}
			}
			
			break;
			
		case KAUTH_FILEOP_LINK:
			if((arg0 == 0) || (arg1 == 0)) {
				LOG_DEBUG("KAUTH_FILEOP_LINK");
			} else {
				if((g_prefix == NULL) || (strprefix((const char *)arg0, g_prefix) || strprefix((const char *)arg1, g_prefix))) {
					//LOG_DEBUG("scope=" KAUTH_SCOPE_FILEOP ", action=KAUTH_FILEOP_LINK, uid=%ld, original=%s, new=%s\n", (long)kauth_cred_getuid(cred), (const char *)arg0, (const char *)arg1);
				}
			}
			
			break;
			
		case KAUTH_FILEOP_EXEC:
			if((g_prefix == NULL) || strprefix((const char *)arg1, g_prefix) ) {
				//LOG_DEBUG("scope=" KAUTH_SCOPE_FILEOP ", action=KAUTH_FILEOP_EXEC, uid=%ld, vnode=0x%lx, path=%s\n",(long)kauth_cred_getuid(cred), (long)arg0, (const char *)arg1);
			}
			
			break;
		*/
		default:
			//LOG_DEBUG("[ERROR] Unknown action (%d)\n", action);
			
			break;
	}
	
	OSDecrementAtomic(&g_activation_count);
	
	return KAUTH_RESULT_DEFER;
}

/*
 *	A kauth listener that's called to authorize an action in any scope that we don't recognise.
 *
 *	See the artile on the top of this file for a detailed explanation of 'arg0' through 'arg3'
 */
static int unk_scope_listener(kauth_cred_t cred, void *data, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
	OSIncrementAtomic(&g_activation_count);
	
	OSDecrementAtomic(&g_activation_count);
	
	return KAUTH_RESULT_DEFER;
}

/*
 *	Removes installed listener + clean up.
 */
kern_return_t remove_kauth_listener(void)
{
	/* prevent any more threads entering our listener */
	if(g_listener != NULL) {
		kauth_unlisten_scope(g_listener);
		
		g_listener = NULL;
	}
	
	/*
	 * there's still a race condition here; there could still be a thread executing between
	 * the OSDecrementAtomic and the return from the listener function (e.g. fileop_scope_listener)
	 *
	 * the window is very small and this only happens during reconfiguration (which it's not supposed to happen a lot)
	 *
	 * running this loop once is enough
	 */
	do {
		struct timespec onesec;
		
		onesec.tv_sec  = 1;
		onesec.tv_nsec = 0;
		
		(void)msleep(&g_activation_count, NULL, PUSER, NULL, &onesec);
	} while(g_activation_count > 0 );
	
	/*
	 * g_listener_scope is accessed by the listener callbacks without any form of lock
	 * so we don't destroy them until after all listener callbacks have drained
	 */
	if(g_listener_scope != NULL) {
		_FREE(g_listener_scope, M_TEMP);
		
		g_listener_scope = NULL;
	}
	
	g_prefix = NULL;
	
	return KERN_SUCCESS;
}

/*
 *	Installs a listener for the specified scope. Parameters 'scope' and 'scopelen' specifies which scope to listen for
 *
 *	The parameter 'prefix' is for the scope listener and may be NULL
 */
static kern_return_t install_listener(const char *scope, size_t scopelen, const char *prefix)
{
	kauth_scope_callback_t callback;
	
	g_listener_scope = _MALLOC(scopelen + 1, M_TEMP, M_WAITOK);
	
	if(g_listener_scope == NULL) {
		return KERN_FAILURE;
	} else {
		memcpy(g_listener_scope, scope, scopelen);
		
		g_listener_scope[scopelen] = 0;
		g_prefix = prefix;
		
		/* register the appropriate listener with kauth */
		if(strcmp(g_listener_scope, KAUTH_SCOPE_GENERIC) == 0) {
			callback = scope_listener;
		} else if(strcmp(g_listener_scope, KAUTH_SCOPE_PROCESS) == 0) {
			callback = process_scope_listener;
		} else if(strcmp(g_listener_scope, KAUTH_SCOPE_VNODE) == 0) {
			callback = vnode_scope_listener;
		} else if(strcmp(g_listener_scope, KAUTH_SCOPE_FILEOP) == 0) {
			callback = fileop_scope_listener;
		} else {
			callback = unk_scope_listener;
		}
		
		g_listener = kauth_listen_scope(g_listener_scope, callback, NULL);
		
		if(g_listener == NULL) {
			return KERN_FAILURE;
		}
		
		return KERN_SUCCESS;
	}
	
	/* if fail, clean up */
	if(g_listener_scope == NULL || g_listener == NULL) {
		return remove_kauth_listener();
	}
}

/*
 *	This is responsible for parsing the new configuration string and updating the listener
 */
static kern_return_t config_kauth(const char *config)
{
	/* remove the existing listener */
	remove_kauth_listener();
	
	/* parse the configuration string and install the new listener */
	if(strcmp(config, "remove") == 0) {
		return KERN_SUCCESS;
	} else if(strprefix(config, "add ")) {
		const char *cursor;
		const char *scope_start;
		const char *scope_end;
		const char *prefix_start;
		
		/* skip the "add " prefix */
		cursor = config + strlen("add ");
		
		/* work out the span of the scope */
		scope_start = cursor;
		
		while((*cursor != ' ') && (*cursor != 0)) {
			cursor += 1;
		}
		
		scope_end = cursor;
		
		if(scope_start == scope_end) {
			return KERN_FAILURE;
		} else {
			/* look for a prefix */
			if(*cursor == ' ') {
				cursor += 1;
			}
			
			if(*cursor == 0) {
				prefix_start = NULL;
			} else {
				prefix_start = cursor;
			}
			
			return install_listener(scope_start, scope_end - scope_start, prefix_start);
		}
	} else {
		return KERN_FAILURE;
	}
}

/*
 *	Initialize the listener.
 */
kern_return_t init_kauth_listener(void)
{
	if(config_kauth(g_config) != KERN_SUCCESS) {
		/* clean up if failed */
		remove_kauth_listener();
	}
	
	return KERN_SUCCESS;
}
