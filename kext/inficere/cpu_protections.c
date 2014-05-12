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

#include "cpu_protections.h"

/*
 *	Enable the Write Protection bit in CR0 register
 */
kern_return_t wp_on(void)
{
	uintptr_t cr0;
	
	/* get current value */
	cr0 = get_cr0();
	
	/* add the WP bit... */
	cr0 = cr0 | CR0_WP;
	
	/* ...and write it back */
	set_cr0(cr0);
	
	/* verify */
	if((get_cr0() & CR0_WP) != 0)
		return KERN_SUCCESS;
	else
		return KERN_FAILURE;
}

/*
 *	Disabled the Write Protection bit in CR0 register so we can modify kernel code
 */
kern_return_t wp_off(void)
{
	uintptr_t cr0;
	
	cr0 = get_cr0();
	cr0 = cr0 & ~CR0_WP;
	
	set_cr0(cr0);
	
	if((get_cr0() & CR0_WP) == 0)
		return KERN_SUCCESS;
	else
		return KERN_FAILURE;
}

/*
 *	Check if WP is set or not
 */
uint8_t wp_verify(void)
{
	uintptr_t cr0;
	
	cr0 = get_cr0();
	
	if(cr0 & CR0_WP)
		return 0;
	else
		return 1;
}


/*
 *	Enable/disable kernel write
 */
void kwrite_on(void)
{
	int_off();
	
	wp_off();
}

void kwrite_off(void)
{
	wp_on();
	
	int_on();
}
