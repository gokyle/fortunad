## fortunad: an entropy daemon


### OVERVIEW

`fortunad` presents a TCP socket from which random data can be
read. The program uses the Fortuna PRNG (with AES-256 and SHA-256 as
the cryptographic building blocks), and obtains initial seed data from
a combination of the Go standard library's `crypto/rand.Reader` , the
system's TPM, and the SHA-256 digest of the nanosecond component of the
current timestamp. Every six hours and after each time 2^32 - 1 bytes
have been read from the PRNG, the system will "stir" the PRNG with new
data from the previous two sources. A seed file is used to preserve the
PRNG's state; however, even if a seed file exists, the PRNG is stirred on
startup. Every ten minutes and on shutdown, the seed file is updated.
Also, on every connection, the nanosecond component of the current
timestamp is written to the PRNG to add additional entropy.


### NOTES

This has only been tested on Linux. It requires a TSPI stack (expecting
trousers and libtspi). For example, on Ubuntu / Debian:

	sudo apt-get install trousers libtspi-dev

The server requires a working TPM, but it doesn't require taking ownership
or additional authentication: the TPM RNG is publicly available.

The server defaults to using port 4141 on 127.0.0.1, using the seed file
`fortuna.seed`.


### LICENSE

> Copyright (c) 2014 Kyle Isom <kyle@tyrfingr.is>
> 
> Permission to use, copy, modify, and distribute this software for any
> purpose with or without fee is hereby granted, provided that the above 
> copyright notice and this permission notice appear in all copies.
> 
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
> WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
> MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
> ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
> WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
> ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
> OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
