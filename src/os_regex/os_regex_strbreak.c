/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_regex.h"
#include "os_regex_internal.h"
#include "shared.h"


/* Split a string into multiples pieces, divided by a char "match".
 * Returns a NULL terminated array on success or NULL on error.
 */
char **OS_StrBreak(char match, const char *str, size_t size, int scape_match)
{
    size_t count = 0;
    size_t i = 0;
    int pos = 0;
    int pos_aux = 0;
    int elemts = 0;
    char *tmp_str;
    char **ret;

    /* We can't do anything if str is null */
    if (str == NULL) {
        return (NULL);
    }

    elemts = strlen(str);
    os_calloc(elemts + 1, sizeof(char), tmp_str);

    os_calloc(size + 1, sizeof(char *), ret);

    /* Allocate memory to null */
    while (i <= size) {
        ret[i] = NULL;
        i++;
    }

    while (*str != '\0') {
        pos = strcspn(str, &match);

		if (elemts = strlen(str), elemts == pos) {
			break;
		}

        /* If before match value exists backslash and scape_match is 1, skip it. */
        while(scape_match && pos > 0 && str[pos-1] == '\\') {

            strncpy(tmp_str, str, pos - 1);
            tmp_str[pos - 1] = '\0';
            strcat(tmp_str, str + pos);
            str = tmp_str;
            pos_aux = strcspn(str + pos, &match);
            pos += pos_aux;
        }

        if ((count < size - 1)) {
            os_calloc(pos + 1, sizeof(char), ret[count]);

            /* Copy the string */
            ret[count][pos] = '\0';
            strncpy(ret[count], str, pos);
            count++;

            elemts = strlen(str);
            if(elemts < pos + 1) {
                break;
            }

            str += pos + 1;
            continue;
        }

        str++;
    } /* leave from here when *str == \0 */

    /* Just do it if count < size */
    if (count < size) {

        /* Copy the string */
        os_calloc(pos + 1, sizeof(char), ret[count]);
        strcpy(ret[count], str);
        count++;

        /* Make sure it is null terminated */
        ret[count] = NULL;
        os_free(tmp_str);

        return (ret);
    }

    /* We shouldn't get to this point
     * Just let "error" handle that
     */

    for (i = 0; ret[i]; i++) {
        os_free(ret[i]);
    }

    os_free(tmp_str);
    os_free(ret);
    return NULL;
}
