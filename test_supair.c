/**
 * Unit tests for the pure pairing logic in pam_supair.c.
 *
 * The module source is included directly with PAM_SUPAIR_UNIT_TEST defined,
 * which excludes the PAM-dependent parts so the tests build and run without
 * libpam. Run via `make test`.
 *
 * Copyright (C) 2011 Stanislaw T. Findeisen <stf at eisenbits.com>
 * Licensed under the GNU General Public License v3 or later.
 */

#define PAM_SUPAIR_UNIT_TEST
#include "pam_supair.c"

#include <stdio.h>

static int g_failures = 0;

static void check(const char *arg, const char *req, const char *targ, int want) {
    int got = matchPairArg(arg, req, targ);
    if (got != want)
        ++g_failures;
    printf("[%s] matchPairArg(\"%s\", \"%s\", \"%s\") = %d (want %d)\n",
           (got == want) ? "ok  " : "FAIL", arg, req, targ, got, want);
}

static void check_sane(const char *name, int want) {
    int got = isUserNameSane(name);
    if (got != want)
        ++g_failures;
    printf("[%s] isUserNameSane(\"%s\") = %d (want %d)\n",
           (got == want) ? "ok  " : "FAIL", name, got, want);
}

int main(void) {
    /* intended pairs match */
    check("alice,bob:root,charlie", "alice",   "root",    1);
    check("alice,bob:root,charlie", "bob",     "charlie", 1);
    check("charlie:bob",            "charlie", "bob",     1);
    check("alice:root",             "alice",   "root",    1);
    check("a,alice,b:x,root,y",     "alice",   "root",    1);

    /* exact matching: substrings must NOT match (regression tests) */
    check("alice,bob:root,charlie", "ali",     "root",    0);
    check("alice,bob:root,charlie", "alice",   "roo",     0);
    check("alice,bob:root,charlie", "bo",      "char",    0);
    check("postgres:root",          "post",    "root",    0);
    check("root:rootadmin",         "root",    "root",    0);

    /* well formed but not a member */
    check("alice,bob:root,charlie", "mallory", "root",    0);
    check("alice,bob:root,charlie", "alice",   "mallory", 0);

    /* malformed arguments (not exactly one ':') */
    check("no-colon-here",          "alice",   "root",   -1);
    check("a:b:c",                  "a",       "b",      -1);

    /* user name sanity */
    check_sane("alice", 1);
    check_sane("a:b",   0);
    check_sane("a,b",   0);

    if (g_failures) {
        printf("\n%d test(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nall tests passed\n");
    return 0;
}
