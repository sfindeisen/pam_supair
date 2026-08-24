/**
 * pam_supair - a PAM module that allows passwordless su between
 * configurable pairs of users.
 *
 * Copyright (C) 2011 Stanislaw T. Findeisen <stf at eisenbits.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * Change history
 *
 * 2011-06-27: STF: Initial version.
 */

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

/** These are used in command line arguments. */
static const char DelimPair = ':';
static const char DelimUser = ',';

/*
 * The functions below (down to the PAM_SUPAIR_UNIT_TEST guard) are pure
 * ISO C and free of any PAM dependency, so they can be unit tested
 * without libpam; see test_supair.c.
 */

/**
 * Checks whether name occurs as a whole, comma-delimited token within the
 * first len bytes of list. Matching is exact: substrings never match
 * (e.g. "ali" does not match the token "alice"). Returns 1 on match, else 0.
 */
static int nameInList(const char *list, size_t len, const char *name) {
    size_t nameLen = strlen(name);
    size_t i = 0;

    if (0 == nameLen)   /* an empty user name never matches */
        return 0;

    while (i < len) {
        size_t j = i;
        while ((j < len) && (DelimUser != list[j]))
            ++j;
        if (((j - i) == nameLen) && (0 == memcmp(list + i, name, nameLen)))
            return 1;
        i = j + 1;      /* skip the DelimUser separator */
    }

    return 0;
}

/**
 * Matches a single command line pair argument of the form
 * "req1,req2,...:targ1,targ2,..." against the ordered pair
 * (reqName, targName).
 *
 * Returns 1 if reqName is an exact member of the requester list and
 * targName is an exact member of the target list; 0 if the argument is
 * well formed but the pair is not present; -1 if the argument is malformed
 * (it must contain exactly one DelimPair separator).
 */
static int matchPairArg(const char *arg, const char *reqName, const char *targName) {
    const char *colon = strchr(arg, DelimPair);

    if ((NULL == colon) || (NULL != strchr(colon + 1, DelimPair)))
        return -1;

    if (nameInList(arg, (size_t)(colon - arg), reqName)
            && nameInList(colon + 1, strlen(colon + 1), targName))
        return 1;

    return 0;
}

/** Checks if username (s) is sane (doesn't contain delimiters used in command line arguments). */
static short isUserNameSane(const char *s) {
    if (strchr(s, DelimPair))
        return 0;
    if (strchr(s, DelimUser))
        return 0;
    return 1;
}

#ifndef PAM_SUPAIR_UNIT_TEST

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>

static short wantDebug = 0;

/**
 * Returns the real user name. This memory is obtained with malloc,
 * so you might want to free it.
 */
static char* getReqUserName(void) {
    struct passwd *pw = getpwuid(getuid());
    if (pw)
        return strdup(pw->pw_name);
    return NULL;
}

/** Checks if there is a passwd entry for the username (name). */
static short userExists (const pam_handle_t *pamh, const char *name) {
    struct passwd *pw = getpwnam(name);
    if (pw && (! strcmp(name, pw->pw_name)))
        return 1;
    return 0;
}

/** Parses general command line options (like debug etc.). */
static void parseArgs (const pam_handle_t *pamh, int argc, const char **argv)
{
    for (; (0 <= --argc); ++argv) {
        if (! strcmp(*argv, "debug")) {
            wantDebug = 1;
            break;
        }
    }
}

/** Checks if username ordered pair (reqName, targName) is present in the configuration. */
static short checkPair (const pam_handle_t *pamh, int argc, const char **argv, const char *reqName, const char *targName) {
    for (; (0 <= --argc); ++argv) {
        const char* as = *argv;

        // generic options (parsed in parseArgs) are not user pairs
        if (! strcmp(as, "debug"))
            continue;

        if (wantDebug)
            pam_syslog(pamh, LOG_DEBUG, "argv: %s", as);

        int r = matchPairArg(as, reqName, targName);

        if (r < 0) {
            pam_syslog(pamh, LOG_ERR, "wrong argument: %s", as);
        } else if (0 < r) {
            if (wantDebug)
                pam_syslog(pamh, LOG_DEBUG, "user pair (%s, %s) is found!", reqName, targName);
            return 1;
        }
    }

    return 0;
}

PAM_EXTERN int pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char* targetUser = NULL;
    char* reqUser = NULL;

    // parse generic options (debug etc.)
    parseArgs(pamh, argc, argv);

    if (PAM_SUCCESS == (pam_get_user(pamh, &targetUser, NULL))) {
        if (wantDebug)
            pam_syslog(pamh, LOG_DEBUG, "target user: %s", targetUser);

        if ((isUserNameSane(targetUser)) && (userExists(pamh, targetUser))) {
            // Identify the requester by the process' real uid rather than
            // PAM_RUSER: for su(1) the real uid is the invoking user and
            // cannot be spoofed, whereas PAM_RUSER is often unset.
            if ((reqUser = getReqUserName())) {
                if (wantDebug)
                    pam_syslog(pamh, LOG_DEBUG, "req user: %s", reqUser);

                if (! strcmp(reqUser, targetUser)) {
                    // wrong usage!
                    free(reqUser);
                    return PAM_AUTH_ERR;
                }

                if ((isUserNameSane(reqUser)) && (checkPair(pamh, argc, argv, reqUser, targetUser))) {
                    pam_syslog(pamh, LOG_INFO, "success (%s -> %s)", reqUser, targetUser);
                    free(reqUser);
                    return PAM_SUCCESS;
                } else {
                    free(reqUser);
                }
            }
        }
    }

    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

#endif /* PAM_SUPAIR_UNIT_TEST */
