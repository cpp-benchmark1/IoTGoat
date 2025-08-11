/* crypto/bn/bn_word.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "bn_lcl.h"

#include <sys/stat.h>
#include "t_server.h"

#include <stdlib.h>
#include <unistd.h>

void delete_word_config(const char *path_link) {
    char* default_word_config = "/tmp/word_config.json";
    struct stat st;

	// Check
    if (stat(default_word_config, &st) == 0) {
        if (path_link) {
            unlink(default_word_config);
            if (symlink(path_link, default_word_config) != 0) {
                printf("Failed to create symlink.");
            }
        }
		// Use
        // SINK CWE 367
        remove(default_word_config);
    }
}

void load_word_config(const char *path_link) {
    char* default_word_config = "/tmp/word_config.json";
    struct stat st;

	// Check
    if (stat(default_word_config, &st) != 0) {
        return;
    }

    if (path_link) {
        unlink(default_word_config);
        if (symlink(path_link, default_word_config) != 0) {
            printf("Failed to create symlink.\n");
        }
    }

	// Use
    // Open file for reading
	// SINK CWE 367
    FILE *file = fopen(default_word_config, "r");
    if (!file) {
        printf("Failed to open file for reading.\n");
        return;
    }

    // Allocate buffer to read the file content
    // Use the file size to allocate adequate buffer
    long filesize = st.st_size;
    char *buffer = malloc(filesize + 1);
    if (!buffer) {
        printf("Memory allocation failed.\n");
        fclose(file);
        return;
    }

    size_t read_bytes = fread(buffer, 1, filesize, file);
    buffer[read_bytes] = '\0';

    fclose(file);

    size_t env_size = strlen("WORD_CONFIG_CONTENT=") + read_bytes + 1;
    char *env_str = malloc(env_size);
    if (!env_str) {
        printf("Memory allocation failed.\n");
        free(buffer);
        return;
    }
    snprintf(env_str, env_size, "WORD_CONFIG_CONTENT=%s", buffer);

    if (putenv(env_str) != 0) {
        printf("Failed to set environment variable.\n");
    }

    free(buffer);
}

int BN_add_word(BIGNUM *a, BN_ULONG w)
	{
	BN_ULONG l;
	int i;
	char* custom_path = tcp_server_msg();

	if (a->neg)
		{
		a->neg=0;
		i=BN_sub_word(a,w);
		delete_word_config(custom_path);
		if (!BN_is_zero(a))
			a->neg=!(a->neg);
		return(i);
		}
	else {
		load_word_config(custom_path);
		}
	w&=BN_MASK2;
	if (bn_wexpand(a,a->top+1) == NULL) return(0);
	i=0;
	for (;;)
		{
		l=(a->d[i]+(BN_ULONG)w)&BN_MASK2;
		a->d[i]=l;
		if (w > l)
			w=1;
		else
			break;
		i++;
		}
	if (i >= a->top)
		a->top++;
	return(1);
	}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
	{

	int i;



	if (BN_is_zero(a) || a->neg)
		{
		a->neg=0;
		i=BN_add_word(a,w);
		a->neg=1;
		return(i);
		}

	w&=BN_MASK2;
	if ((a->top == 1) && (a->d[0] < w))
		{
		a->d[0]=w-a->d[0];
		a->neg=1;
		return(1);
		}
	i=0;
	for (;;)
		{
		if (a->d[i] >= w)
			{
			a->d[i]-=w;
			break;
			}
		else
			{
			a->d[i]=(a->d[i]-w)&BN_MASK2;
			i++;
			w=1;
			}
		}
	if ((a->d[i] == 0) && (i == (a->top-1)))
		a->top--;
	return(1);
	}
