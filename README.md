# GNU patch vulnerabilities

I identified several vulnerabilities in the GNU patch utility, most of them making it possible to execute 
arbitrary code if the victim opens a crafted patch file. It also turned out, some of these vulnerabilities
had been silently addressed by the maintainer back then in 2018 when CVE-2018-1000156 was reported, but 
the relevant patch was not picked up by most of the Linux distributions.

## CVE-2018-1000156 - unrestricted ed input

This finding belongs to someone else, but unfortunately I'm unsure who the author is.
The original thread on the official bug report site:

https://savannah.gnu.org/bugs/?53566

## CVE-2019-13638 - Shell command injection while invoking ed

## CVE-2019-13636 - Directory traversal and arbitrary file append with (almost) arbitrary file content.

## CVE-2018-20969 - OS shell execution via unrestricted ed filename

(Yes, this one was reported by me in 2019 and MITRE indeed assigned a 2018 ID for it)
