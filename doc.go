/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


/*
A Public key cryptosystem based on eighter discrete logarithms or elliptic curves.
This Package implements a fully integrated Public Key System. Every Keypair can
be used for both, signatures and encryption. The Encryption is done using a simple
Diffie-Hellman-Scheme with symetric cipher. The signature scheme is based on
Schnorr's signature (see https://en.wikipedia.org/wiki/Schnorr_signature ).

For Encryption, the cipher Twofish ist used in 256-bit mode. For Hashing
(Schnorr signature) BLAKE2b is used, where BLAKE2b is used as keyed MAC.
*/
package generalcryptosystem


