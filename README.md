# SECCOMP-PMOCCES
Parsing syscalls in usermode using SecComp, because why not?

# Overview
So there was a recent-ish update to the Linux Kernel to allow you to use Secccomp
to [intercept and parse syscalls in userspace](https://www.youtube.com/watch?v=sqvF_Mdtzgg).

That talk does give some good reasonings for it, but I personally found it a bit surprising that
this was the correct solution to the problem.

Nonetheless I though it fun to look into how this works, and make a silly program.

`Pmocces` (Seccomp backwards) will launch a shell, then use seccomp to intercept all `execve` syscalls,
and then swap around the letters in the binary name (but not the path) - e.g. `/bin/whoami` is turned into `/bin/imaohw`.

To do anything in the shell, you must use full paths, and type the binary names backwards.
As the parsing is done in userland, there is **NO GUARANTEE** this won't all blow up and crash things due to memory
being changed underneeth it.

# Build
```bash
git clone git@github.com:pathtofile/seccomp-pmocces.git
cd seccomp-pmocces
make
```

# Run
```bash
$> sudo ./pmocces
# This launches a shell, now try to do things?
$> whoami
/bin/sh: 1: whoami: not found
$> /usr/bin/imaohw
root
```

# Why
Moslty to learn how Seccomp and this new notify stuff works.


# Aknowledgements
Code heavily borrowed from the [user-trap](https://github.com/torvalds/linux/blob/HEAD/samples/seccomp/user-trap.c)
sample code in the Kernel source Tree, which I believe is written by [Tycho Andersen](https://github.com/tych0).

