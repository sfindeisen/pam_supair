# pam_supair

A PAM module that allows `su(1)` without typing a password between specified
pairs of users. This is useful if you have a configuration where a single
human user switches frequently between multiple system users to perform
various tasks.

pam_supair is a PAM module for use with `su(1)` that authenticates the user
if and only if that user's name (obtained via that user's real id) and su's
target user name (obtained via `pam_get_user(3)`) form a pair that is allowed
by the configuration. Multiple user pairs can be specified.

## Examples

In `/etc/pam.d/su` :

```
auth   sufficient   pam_supair.so alice,bob:root,charlie charlie:bob debug
```

This specifies that users `alice` and `bob` can each do passwordless `su` to
users `root` and `charlie`. User `charlie` can do passwordless `su` to user
`bob`. The optional `debug` parameter is present `=>` some info will be
logged via `pam_syslog(3)`.
