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
 *
 *
 *	These are quick, hacky and dirty helper functions.
 *
 */

#include <mach/mach_types.h>
#include <sys/kernel_types.h>
#include <sys/attr.h>
#include <sys/malloc.h>
#include <string.h>
#include "data_def.h"

struct _mhead {
	size_t	mlen;
	char	dat[0];
};

/* TODO */
int is_hash_valid(char *s)
{
	int i;
	size_t len = 0;
	
	if(s) {
		len = strlen(s);
		
		if((len == 32) || (len == 40)) {
			for(i=0; i<len; i++) {
				int c = (int)s[i];
				
				if((c < 48 || c > 57) && (c < 65 || c > 90) && (c < 97 || c > 122))
					return 0;
			}
			
			/* valid hash */
			return 1;
		}
	}
	
	/* invalid */
	return 0;
}

#pragma mark Memory functions (for Capstone)

void *ifc_calloc(size_t num, size_t size)
{
	if(size == 0 || num == 0)
		return NULL;
	
	size_t total = num * size;
	void *p = _MALLOC(total, M_TEMP, M_WAITOK);
	
	if(p == NULL)
		return NULL;
	
	return memset(p, 0, total);
}

void ifc_free(void *ptr)
{
	if(ptr != NULL)
		_FREE(ptr, M_TEMP);
}

void *ifc_malloc(size_t size)
{
	return _MALLOC(size, M_TEMP, M_WAITOK);
}

void *ifc_realloc(void *ptr, size_t size)
{
	struct _mhead *hdr;
	void *newaddr;
	size_t alloc;
	
	/* realloc(NULL, ...) is equivalent to malloc(...) */
	if(ptr == NULL)
		return _MALLOC(size, M_TEMP, M_WAITOK);
	
	/* allocate a new block */
	newaddr = _MALLOC(size, M_TEMP, M_WAITOK);
	
	if(newaddr == NULL)
		return NULL;
	
	hdr = ptr;
	--hdr;
	alloc = hdr->mlen - sizeof(*hdr);
	
	/* copy over original contents */
	bcopy(ptr, newaddr, MIN(size, alloc));
	_FREE(ptr, M_TEMP);
	
	return newaddr;
}
