pam_supair
==========

A PAM module that allows su(1) without password between specified pairs of users.

pam_supair is a PAM module for use with su(1) that authenticates the user iff
that user's name (obtained via that user's real id) and su's target user name
(obtained via pam_get_user(3)) form a pair that is allowed by the
configuration. Multiple pairs can be specified.

OPTIONS

debug

    Print debug information.

EXAMPLES

In /etc/pam.d/su :

auth   sufficient   pam_supair.so sf,u2,u3:root,sf2 sf2:u2 debug

This specifies that users sf, u2 and u3 can each do passwordless su to users
root and sf2. User sf2 can do passwordless su to user u2. debug parameter is
present (anywhere on the command line) so some debug information will be
logged via pam_syslog(3).
