#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ---------------------------------------------------
# Copyright (c) 2013 Pablo Caro. All Rights Reserved.
# Pablo Caro <me@pcaro.es> - http://pcaro.es/
# AES_base_generator.py
# ---------------------------------------------------

# This script is used to generate a new Python module (called "AES_base.py"),
# containing the neccesary tables used in standard AES: S-Box and inverted
# S-Box for SubBytes and InvSubBytes transformations, lookup tables for Galois
# Field product x2, x3, x9, x11, x13, x14 used in MixColumns and InvMixColumns,
# and Rcon used in KeyExpansion.
#
# Execution also generates a log containing the same data.
#
# For a complete standard AES Python implementation, see "Python-AES", which
# uses the "AES_base.py" module generated.
#
# Please, have in mind that this code is only intended for educational and
# recreational purposes, and should not be used in secure systems.


import sys


class BinPol:
    """Binary polinomy.

    This class represents a binary polinomy, as well as the defined operations
    in Z2. Note that not every possible operation is implemented, but only the
    needed to generate the AES related tables (see project description).

    """

    def __init__(self, x, irreducible_polynomial=None, grade=None):
        self.dec = x
        self.hex = hex(self.dec)[2:]
        self.bin = reversed(list(bin(self.dec)[2:]))
        self.bin = [int(bit) for bit in self.bin]

        if grade is not None:
            self.grade = grade
        else:
            self.grade = len(self.bin)-1

        self.irreducible_polynomial = irreducible_polynomial

    def __str__(self):
        h = self.hex
        if self.dec < 16:
            h = '0' + h
        return h

    def __repr__(self):
        return str(self)

    def __len__(self):
        return self.grade

    def __setitem__(self, key, value):
        if value in [0, 1]:
            while len(self.bin) <= key:
                self.bin.append(0)

            self.bin[key] = value

        self.__update_from_bin()

    def __getitem__(self, key):
        if key < len(self.bin):
            return self.bin[key]
        else:
            return 0

    def __add__(self, x):
        r = BinPol(self.dec, self.irreducible_polynomial)

        for i, a in enumerate(x.bin):
            r[i] = r[i] ^ a

        r.__update_from_bin()
        return r

    def __mul__(self, x):
        r = BinPol(0, self.irreducible_polynomial)
        for i, a in enumerate(self.bin):
            for j, b in enumerate(x.bin):
                if a and b:
                    r[i+j] = r[i+j] ^ 1

        r.__update_from_bin()
        return r

    def __pow__(self, x):
        r = BinPol(1, self.irreducible_polynomial)

        for i in range(1, x+1):
            r = r * BinPol(self.dec)
            r.__update_from_bin()

            if (r.irreducible_polynomial
                    and r.grade >= r.irreducible_polynomial.grade):
                r = r + r.irreducible_polynomial
                r.__update_from_bin()

        return r

    def __update_from_bin(self):

        self.__remove_most_significant_zeros()

        self.dec = 0
        for i, a in enumerate(self.bin):
            if a:
                self.dec += 2**i

        self.hex = hex(self.dec)[2:]

        self.grade = len(self.bin)-1

    def __remove_most_significant_zeros(self):
        last = 0
        for i, a in enumerate(self.bin):
            if a:
                last = i
        del(self.bin[last+1:])


def inv_pol(pol, antilog, log):
    if pol.dec == 0:
        return BinPol(0, pol.irreducible_polynomial)
    else:
        return BinPol(antilog[0xFF - log[pol.dec].dec].dec,
                      pol.irreducible_polynomial)


def affine_transformation(b):
    b1 = BinPol(b.dec, b.irreducible_polynomial)
    c = BinPol(0b01100011)

    for i in range(8):
        b1[i] = b[i] ^ b[(i+4) % 8]
        b1[i] ^= b[(i+5) % 8]
        b1[i] ^= b[(i+6) % 8]
        b1[i] ^= b[(i+7) % 8]
        b1[i] ^= c[i]

    return b1


def str_16x16(table):
    s = '\t'
    for i in range(16):
        s += hex(i) + '\t'
    s += '\n'

    for i in range(16):
        s += hex(i) + '\t'
        for j in range(16):
            s += str(table[i*16+j]) + '\t'
        s += '\n'

    return s


def generate():
    """This function uses the BinPol class to create the F256 field, the
    logarithm and antilogarithm table, and the needed tables for AES (see
    project description).

    The tables are found as output both in the log ("AES_base.log") and in the
    generated module ("AES_base.py").

    """

    try:
        with open('AES_base.log', 'w') as f:
            f.write('*'*64+'\n')
            f.write('* ' + 'S-Box Generator'.center(60) + ' *\n')
            f.write('*'*64+'\n\n')

            irreducible_polynomial = BinPol(0b100011011)
            f.write('Irreducible polynomial used for creating the F256\
                    field\n')
            f.write(str(irreducible_polynomial) + '\n\n')

            primitive = BinPol(3, irreducible_polynomial)
            f.write('Primitive element of F256 [x + 1]\n')
            f.write(str(primitive) + '\n\n')

            antilog = [primitive**i for i in range(256)]
            f.write('[x + 1] antilogarithm table\n')
            f.write(str_16x16(antilog))
            f.write('\n')

            log = [BinPol(0, irreducible_polynomial)
                   for i in range(256)]
            for i, a in enumerate(antilog):
                log[a.dec] = BinPol(i, irreducible_polynomial)
            f.write('[x + 1] logarithms table\n')
            f.write(str_16x16(log))
            f.write('\n')

            inv = [inv_pol(BinPol(i), antilog, log) for i in range(256)]
            f.write('F256 field inverse table\n')
            f.write(str_16x16(inv))
            f.write('\n')

            sbox = [affine_transformation(a) for a in inv]
            f.write('S-Box table: affine transformation of every inverse\
                    element\n')
            f.write(str_16x16(sbox))
            f.write('\n')

            isbox = [BinPol(0, irreducible_polynomial)
                     for i in range(256)]
            for i, a in enumerate(sbox):
                isbox[a.dec] = BinPol(i, irreducible_polynomial)
            f.write('Inverse S-Box table\n')
            f.write(str_16x16(isbox))
            f.write('\n')

            gfp2 = [antilog[(log[i].dec + log[2].dec) % 255].hex
                    for i in range(256)]
            gfp2[0] = '0'
            f.write('Galois Field x2 product lookup table\n')
            f.write(str_16x16(gfp2))
            f.write('\n')

            gfp3 = [antilog[(log[i].dec + log[3].dec) % 255].hex
                    for i in range(256)]
            gfp3[0] = '0'
            f.write('Galois Field x3 product lookup table\n')
            f.write(str_16x16(gfp3))
            f.write('\n')

            gfp9 = [antilog[(log[i].dec + log[9].dec) % 255].hex
                    for i in range(256)]
            gfp9[0] = '0'
            f.write('Galois Field x9 product lookup table\n')
            f.write(str_16x16(gfp9))
            f.write('\n')

            gfp11 = [antilog[(log[i].dec + log[11].dec) % 255].hex
                     for i in range(256)]
            gfp11[0] = '0'
            f.write('Galois Field x11 product lookup table\n')
            f.write(str_16x16(gfp11))
            f.write('\n')

            gfp13 = [antilog[(log[i].dec + log[13].dec) % 255].hex
                     for i in range(256)]
            gfp13[0] = '0'
            f.write('Galois Field x13 product lookup table\n')
            f.write(str_16x16(gfp13))
            f.write('\n')

            gfp14 = [antilog[(log[i].dec + log[14].dec) % 255].hex
                     for i in range(256)]
            gfp14[0] = '0'
            f.write('Galois Field x14 product lookup table\n')
            f.write(str_16x16(gfp14))
            f.write('\n')

            primitive = BinPol(2, irreducible_polynomial)
            Rcon = [primitive**(i-1) for i in range(256)]
            Rcon[0] = BinPol(0)
            f.write('Round constant table\n')
            f.write(str_16x16(Rcon))
            f.write('\n')

    except Exception as e:
        raise e
        sys.exit()

    try:
        with open('AES_base.py', 'w') as f:
            s = '''
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file has been generated by AES_base_generator.py

sbox = {0}

isbox = {1}

gfp2 = {2}

gfp3 = {3}

gfp9 = {4}

gfp11 = {5}

gfp13 = {6}

gfp14 = {7}

Rcon = {8}
'''.format([i.dec for i in sbox],
           [i.dec for i in isbox],
           [int(i, 16) for i in gfp2],
           [int(i, 16) for i in gfp3],
           [int(i, 16) for i in gfp9],
           [int(i, 16) for i in gfp11],
           [int(i, 16) for i in gfp13],
           [int(i, 16) for i in gfp14],
           [i.dec for i in Rcon])

            f.write(s)

    except Exception as e:
        raise e
        sys.exit()


def main():
    generate()

if __name__ == '__main__':
    main()
