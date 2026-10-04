# TinyOS v2.8 - Multi-User System Test Guide

A manual walkthrough of accounts, authentication and file permissions. Every
output line below is the text the kernel or the ring-3 shell prints; `****`
stands for a password typed at a hidden prompt.

Run it in a window so you can type:

```bash
make run-gui
```

Accounts live only in kernel memory, so every boot starts from step 1.

## Background

- At boot the database holds one account, `root` (uid 0, gid 0), **locked with no
  password**, plus the groups `root` (0) and `users` (100).
- Passwords are hashed with PBKDF2-HMAC-SHA256 (100,000 iterations) and a
  random 16-byte salt.
- Three consecutive failed authentications lock an account for 60 seconds. Login,
  `su` and the current-password check in `passwd` all count, and a success resets
  the count.
- The login shell is the ring-3 shell (`D:/ $` prompt). `kshell` switches to the
  kernel shell (`$ ` prompt), which keeps your identity.

## 1. First boot: set the root password

```
First-Time Setup: Let's Create Your Password
...
This is your first time booting TinyOS!
For security, let's set up a root password.
...
Enter new root password: ****
Confirm new root password: ****

Root password set successfully!
Root account is now active and unlocked.
```

An empty password or a mismatch prints `Password cannot be empty. Please try
again.` or `Passwords do not match. Please try again.` and asks again.

## 2. Log in as root

```
TinyOS login: root
Password: ****

Login successful. Welcome, root!
```

Because root is the only account, TinyOS offers to create a regular user
(`Would you like to create a regular user now? (y/n):`). Answering `y` creates
one with uid 1000. For this walkthrough answer `n`:

```
Skipping user creation.
You can create users later with: useradd <username>
```

The ring-3 shell starts:

```
TinyOS shell (ring 3) - 'help' for builtins, 'kshell' for the kernel shell, 'exit' to log out
D:/ $ id
uid=0 gid=0
```

## 3. Create, change and delete accounts (ring 3)

`useradd`, `userdel` and `passwd` work from the ring-3 shell. The prompts come
from the kernel, so these commands cannot be redirected.

```
D:/ $ useradd alice
Enter password for new user: ****
useradd: user 'alice' created (uid=1002, gid=100)
D:/ $ useradd bob
Enter password for new user: ****
useradd: user 'bob' created (uid=1003, gid=100)
D:/ $ useradd alice
useradd: user 'alice' already exists
useradd: alice: file exists
```

New uids start at 1002. When a command refuses, the kernel's reason is followed
by the shell's errno line, as in the last example.

Root sets another user's password without the old one:

```
D:/ $ passwd alice
Enter new password: ****
Retype new password: ****
passwd: password updated successfully
```

Deletion, and its two refusals:

```
D:/ $ useradd tmpuser
Enter password for new user: ****
useradd: user 'tmpuser' created (uid=1004, gid=100)
D:/ $ userdel tmpuser
userdel: user 'tmpuser' deleted
D:/ $ userdel root
userdel: cannot delete root user
userdel: root: operation not permitted
```

`userdel` also refuses the account you are logged in as
(`userdel: cannot delete the current user`).

## 4. The kernel shell: `users`, `id`, `su`

```
D:/ $ kshell
Switching to the kernel shell; `logout` there returns to login.
$ users
[USER] User list:
  root         uid=    0 gid=    0 home=/root flags=0x01
  alice        uid= 1002 gid=  100 home=/ flags=0x01
  bob          uid= 1003 gid=  100 home=/ flags=0x01
$ id
uid=0(root) gid=0 euid=0 egid=0
$ id alice
uid=1002(alice) gid=100
$ id nobody
id: 'nobody': no such user
```

`flags=0x01` means active. Root can `su` to any account without a password, and
only root is told when the name does not exist:

```
$ su nobody
su: user 'nobody' does not exist
$ su alice
Switching to alice (no password required for root)
Now running as: alice
$ id
uid=1002(alice) gid=100 euid=1002 egid=100
```

The session is now alice's. `logout` returns to the login prompt.

## 5. Unprivileged user: refusals and uniform failures

Log in as alice. In the ring-3 shell:

```
D:/ $ id
uid=1002 gid=100
D:/ $ useradd mallory
useradd: permission denied (must be root)
useradd: mallory: operation not permitted
D:/ $ passwd bob
passwd: only root can change other users' passwords
passwd: bob: operation not permitted
```

Changing your own password asks for the current one first:

```
D:/ $ passwd
Changing password for alice
(current) ****
Enter new password: ****
Retype new password: ****
passwd: password updated successfully
```

A wrong current password prints `passwd: authentication token manipulation
error` and counts toward alice's lockout.

In the kernel shell, a non-root `su` always asks for a password and every failure
reads the same, whether the name is unknown or the password is wrong:

```
D:/ $ kshell
Switching to the kernel shell; `logout` there returns to login.
$ su nobody
Switching to user 'nobody'
Password for nobody: ****
su: authentication failure
$ su bob
Switching to user 'bob'
Password for bob: ****
su: authentication failure
```

Each failure is followed by a short delay. The login prompt behaves the same way:
an unknown name and a wrong password both print

```
Login incorrect
2 login attempts remaining
```

The reason is recorded only in the audit log (`auditlog`, root only).

## 6. File permissions in `/scratch`

`/scratch` is mode 0777, so every user can create files there. New files are
created 0600.

Log in as root:

```
D:/ $ write /scratch/secret.txt top secret
D:/ $ chmod 600 /scratch/secret.txt
D:/ $ stat /scratch/secret.txt
/scratch/secret.txt  size=11  mode=600  file
D:/ $ exit
```

Log in as alice:

```
D:/ $ cat /scratch/secret.txt
cat: /scratch/secret.txt: no such file or directory
D:/ $ chmod 644 /scratch/secret.txt
chmod: /scratch/secret.txt: operation not permitted
```

A file you may not open reads as nonexistent, and only the owner (or root) can
change its mode. Log back in as root, run `chmod 644 /scratch/secret.txt`, then
as alice:

```
D:/ $ cat /scratch/secret.txt
top secret
```

## 7. Account lockout

As alice, in the kernel shell, give `su bob` a wrong password three times. Bob's
account is now locked for 60 seconds: a fourth `su bob`, even with the correct
password, still prints `su: authentication failure`. Wait 60 seconds and the
correct password works again:

```
$ su bob
Switching to user 'bob'
Password for bob: ****
Switched to user: bob
```

While an account is locked, root sees the state directly
(`su: account 'bob' is locked`), and setting a new password with `passwd bob`
clears the lock.

At the login prompt itself the limit is per session: after the third failure it
prints `Too many login failures. Access denied.` and `Login failed. System
halted.`, and the VM must be restarted (which also resets the accounts).

## See also

- [`USER_GUIDE.md`](USER_GUIDE.md) - boot, login and both shells
- [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md) - the authentication and
  permission mechanisms
