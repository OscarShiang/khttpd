# khttpd

`khttpd` is an experimental HTTP server implemented as Linux kernel module.
The server defaults to port 8081, but this can be easily configured using
command line argument `port=?` when you are about to load the kernel module.

## TODO
* Release resources when HTTP connection is about to be closed.
* Introduce CMWQ.
* Improve memory management.
* Request queue and/or cache

## License

`khttpd` is released under the MIT License. Use of this source code is governed by
a MIT License that can be found in the LICENSE file. 

External source code:
* `http_parser.[ch]`: taken from [nodejs/http-parser](https://github.com/nodejs/http-parser)
  - Copyrighted by Joyent, Inc. and other Node contributors.
  - MIT License
* `htstress.c`: derived from [htstress](https://github.com/arut/htstress)
  - Copyrighted by Roman Arutyunyan
  - 2-clause BSD license
