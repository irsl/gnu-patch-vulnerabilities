# GNU patch vulnerabilities

I identified several vulnerabilities in the GNU patch utility, most of them making it possible to execute 
arbitrary code if the victim opens a crafted patch file. It also turned out, some of these vulnerabilities
had been silently addressed by the maintainer back then in 2018 when CVE-2018-1000156 was reported, but 
the relevant patch was not picked up by most of the Linux distributions.
