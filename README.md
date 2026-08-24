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

User names are matched exactly (whole names), so configuring `charlie` never
grants anything to `char` or `charlie2`.

In your Bash-like shell you can then type:

```shell
alice@localhost$ su - charlie
charlie@localhost$
```

Voila!

## Installation

This requires PAM development C headers to compile. On a Debian-like system
they are contained in `libpam-dev` package (`apt-get install libpam-dev`).

Then build (and optionally run the unit tests):

```shell
make
make test
```

Install the resulting `pam_supair.so` into your PAM module directory:

```shell
make install
```

By default it is installed under `/lib/<multiarch>/security/`. Override the
destination if needed, e.g. `make install SECURITYDIR=/usr/lib/x86_64-linux-gnu/security`
(`DESTDIR` is also honoured for staged installs). Finally, edit your
`/etc/pam.d/su` as required.
