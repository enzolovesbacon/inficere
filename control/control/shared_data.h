/*
 * Copyright (c) fG!, 2011, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Original code from "onyx-the-black-cat" modified by Enzo Matsumiya (@enzolovesbacon).
 */

#ifndef control_shared_data_h
#define control_shared_data_h

#define BUNDLE_ID   "com.enzo.inficere"

#define SET_PID			0x1
#define ANTI_PTRACE_ON		0x2
#define ANTI_PTRACE_OFF		0x3
#define ANTI_KILL_ON		0x4
#define ANTI_KILL_OFF		0x5
#define ANTI_SYSCTL_ON		0x6
#define ANTI_SYSCTL_OFF		0x7
//#define RESERVED		0x8
//#define RESERVED		0x9
#define HIDE_FILE_ON		0xa
#define HIDE_FILE_OFF		0xb
#define GIVE_ROOT		0xc
#define HOOK_IPF_ON		0xd
#define HOOK_IPF_OFF		0xe
#define PATCH_TASK_FOR_PID	0xf
#define UNPATCH_TASK_FOR_PID	0x10
#define ANTI_KAUTH_ON		0x11
#define ANTI_KAUTH_OFF		0x12
#define PATCH_RESUME_FLAG	0x13
#define UNPATCH_RESUME_FLAG	0x14
#define PATCH_SINGLESTEP	0x15
#define UNPATCH_SINGLESTEP	0x16
#define HIDE_USER_ON		0x17
#define HIDE_USER_OFF		0x18

#endif
