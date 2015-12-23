# oauthtools
Low level tools for working with Open Auth 2.0

Using parts of code from liboauth.

oat_url_escape benchmark Intel Core i5 using 64k array of 31 char strings with random 1 to 128 values:
```
liboauth:   0.252094ms
oauthtools: 0.006649ms
libcurl:    0.214187ms
```
Looks like MSVC doing some sort of inlining oauthtools version of this func, which it shouldn't. I'm too lazy to lurk in asm right now.
