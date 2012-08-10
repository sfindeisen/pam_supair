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

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>

/** These are used in command line arguments. */
static const char DelimPair = ':';
static const char DelimUser = ',';
static short wantDebug = 0;

/**
 * Returns the real user name. This memory is obtained with malloc,
 * so you might want to free it.
 */
static char* getReqUserName() {
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

/** Checks if username (s) is sane (doesn't contain delimiters used in command line arguments). */
static short isUserNameSane(const char *s) {
    if (index(s, DelimPair))
        return 0;
    if (index(s, DelimUser))
        return 0;
    return 1;
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
        
        if (wantDebug)
            pam_syslog(pamh, LOG_DEBUG, "argv: %s", as);

        const char* p1 =  index(as, DelimPair);
        const char* p2 = rindex(as, DelimPair);

        if (p1 && (p1 == p2)) {
            const char* pr = strstr(as, reqName);
            if (pr && (pr < p1)) {
                const char* pt = strstr(as, targName);
                for (; pt && pt <= p1; pt = strstr(1 + pt, targName));
                if (pt && (p1 < pt)) {
                    if (wantDebug)
                        pam_syslog(pamh, LOG_DEBUG, "user pair (%s, %s) is found!", reqName, targName);
                    return 1;
                }
            }
        } else {
            pam_syslog(pamh, LOG_ERR, "wrong argument: %s", as);
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
            // TODO pam_get_item(... PAM_RUSER ...) instead??
            if ((reqUser = getReqUserName(pamh))) {
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
