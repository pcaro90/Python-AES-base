Python-AES-base
===============

Generator for S-Box, inverted S-Box, lookup tables for Galois Field product,
and Rcon.

This scripts implements a Binary Polynomial class, used to generate te
neccesary tables used in the AES algorithm: S-Box and inverted S-Box for
SubBytes and InvSubBytes transformations, lookup tables for Galois Field
product x2, x3, x9, x11, x13, x14 used in MixColumns and InvMixColumns, and
Rcon used in KeyExpansion.

After the execution of the module, a new "AES_base.py" file will be created,
and it can be imported as Python module, which can be used by a Python AES
program. For a complete standard AES Python implementation, chech
[Python-AES](https://github.com/pcaro90/Python-AES/). Execution also generates
a log containing the same data.

This code is only intended for educational and recreational purposes, and
should not be used in secure systems.

License
-------

Copyright (c) 2013 Pablo Caro. All Rights Reserved.

Pablo Caro <<me@pcaro.es>> - <http://pcaro.es/>

See LICENSE file
