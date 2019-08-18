# pam_supair

A PAM module that allows `su(1)` without typing a password between specified
pairs of users. This is useful if you have a configuration where a single
human user switches frequently between multiple system users to perform
various tasks.

pam_supair is a PAM module for use with `su(1)` that authenticates the user
if and only if the current user and the target user form a pair that is
allowed by the configuration. Multiple user pairs can be specified.

Together with pam_xauth(8) this makes it easier to forward xauth keys
between users.

## Example

In `/etc/pam.d/su` :

```
auth   sufficient   pam_supair.so alice,bob:root,charlie charlie:bob debug
```

This specifies that users `alice` and `bob` can each do passwordless `su` to
users `root` and `charlie`. User `charlie` can do passwordless `su` to user
`bob`. The optional `debug` parameter is present => the operation will be
logged by syslog.

In your Bash-like shell you can then type:

```shell
alice@localhost $ su - charlie
charlie@localhost $
```

Voila!

## Installation

This requires PAM development C headers to compile. On a Debian-like system
they are contained in `libpam-dev` package.

Then:

```shell
make
```

Now copy the resulting `pam_supair.so` into your PAM module directory (`/lib/x86_64-linux-gnu/security/` on my machine) and edit your `/etc/pam.d/su` as required.
