# pam_supair

A simple PAM module that allows `su(1)` without a password between configured
pairs of users.

## Example

In `/etc/pam.d/su` :

```
auth   sufficient   pam_supair.so alice,bob:root,charlie charlie:bob debug
```

This means that users `alice` and `bob` can each do passwordless `su` to
users `root` and `charlie`. User `charlie` can do passwordless `su` to user
`bob`. The optional `debug` parameter is present => the operation will be
logged by syslog (each time).

In your Bash-like shell you can then type:

```shell
alice@localhost$ su - charlie
charlie@localhost$
```

Voila!

## Installation

This requires PAM development C headers to compile. On a Debian-like system
they are contained in `libpam-dev` package (`apt-get install libpam-dev`).

Then:

```shell
make
```

Now copy the resulting `pam_supair.so` file into your PAM module directory
(`/lib/x86_64-linux-gnu/security/` on my machine) and edit your
`/etc/pam.d/su` as required.
