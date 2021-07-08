# Windows DNS API (GoLang)
===========

This is a simple API based on the [Win DNS API (Node. JS)](https://github.com/vmadman/win-dns-api). This fork adds JWT authentication.

This tool acts as an API for Windows Server DNS. With this it is possible to create/edit/delete DNS entries on a Windows Server.
To run this as a service take a look at [NSSM](http://nssm.cc/)

Authentication is used using JWT tokens and the [jwtauthapi](https://bitbucket.org/HelgeOlav/jwtauthrequest/src/master/jwtauthapi/) library.
The JWT validation configuration is loaded from the file "config.json" in the current directory.