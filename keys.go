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

package generalcryptosystem

import "math/big"

type Group uint
const (
	/* ModP groups (see RFC-3526) */
	Modp5 = Group(iota) /* 1536-bit MODP Group */
	Modp14 /* 2048-bit MODP Group */
	Modp15 /* 3072-bit MODP Group */
	Modp16 /* 4096-bit MODP Group */
	Modp17 /* 6144-bit MODP Group */
	Modp18 /* 8192-bit MODP Group */
	
	/* Curves ... */
	FIPS_P224 /* P-224 (see FIPS 186-3, section D.2.2) */
	FIPS_P256 /* P-256 (see FIPS 186-3, section D.2.3) */
	FIPS_P384 /* P-384 (see FIPS 186-3, section D.2.4) */
	FIPS_P521 /* P-521 (see FIPS 186-3, section D.2.5) */
	
	Koblitz_S160 /* secp160k1 (see SEC 2 section 2.4.1) */
	Koblitz_S192 /* secp192k1 (see SEC 2 section 2.5.1) */
	Koblitz_S224 /* secp224k1 (see SEC 2 section 2.6.1) */
	Koblitz_S256 /* secp256k1 (see SEC 2 section 2.7.1) */
	
	/* Brainpool Curves. (Non-NSA curves) */
	Brainpool_P160r1
	Brainpool_P160t1
	Brainpool_P192r1
	Brainpool_P192t1
	Brainpool_P224r1
	Brainpool_P224t1
	Brainpool_P256r1
	Brainpool_P256t1
	Brainpool_P320r1
	Brainpool_P320t1
	Brainpool_P384r1
	Brainpool_P384t1
	Brainpool_P512r1
	Brainpool_P512t1
	
	/* Complex number groups, see github.com/maxymania/complexdh */
	Complex_2048bit
	Complex_4096bit
	Complex_8192bit
)

const (
	group_ModP = 1
	group_EcFips = 2
	group_EcKoblitz = 3
	group_EcBrainpool = 4
	group_ComplxGroup = 5
)

type ObjectID []int

var groups = make(map[Group]ObjectID)

func (g Group) Valid() bool{
	_,ok := groups[g]
	return ok
}
func (g Group) ID() ObjectID {
	if r,ok := groups[g]; ok { return r }
	return nil
}

func init(){
	groups[Modp5]  = ObjectID{group_ModP, 5}
	groups[Modp14] = ObjectID{group_ModP,14}
	groups[Modp15] = ObjectID{group_ModP,15}
	groups[Modp16] = ObjectID{group_ModP,16}
	groups[Modp17] = ObjectID{group_ModP,17}
	groups[Modp18] = ObjectID{group_ModP,18}
	
	groups[FIPS_P224] = ObjectID{group_EcFips,224}
	groups[FIPS_P256] = ObjectID{group_EcFips,256}
	groups[FIPS_P384] = ObjectID{group_EcFips,384}
	groups[FIPS_P521] = ObjectID{group_EcFips,521}
	
	groups[Koblitz_S160] = ObjectID{group_EcKoblitz,160}
	groups[Koblitz_S192] = ObjectID{group_EcKoblitz,192}
	groups[Koblitz_S224] = ObjectID{group_EcKoblitz,224}
	groups[Koblitz_S256] = ObjectID{group_EcKoblitz,256}
	
	groups[Brainpool_P160r1] = ObjectID{group_EcBrainpool,160,1}
	groups[Brainpool_P160t1] = ObjectID{group_EcBrainpool,160,2}
	groups[Brainpool_P192r1] = ObjectID{group_EcBrainpool,192,1}
	groups[Brainpool_P192t1] = ObjectID{group_EcBrainpool,192,2}
	groups[Brainpool_P224r1] = ObjectID{group_EcBrainpool,224,1}
	groups[Brainpool_P224t1] = ObjectID{group_EcBrainpool,224,2}
	groups[Brainpool_P256r1] = ObjectID{group_EcBrainpool,256,1}
	groups[Brainpool_P256t1] = ObjectID{group_EcBrainpool,256,2}
	groups[Brainpool_P320r1] = ObjectID{group_EcBrainpool,320,1}
	groups[Brainpool_P320t1] = ObjectID{group_EcBrainpool,320,2}
	groups[Brainpool_P384r1] = ObjectID{group_EcBrainpool,384,1}
	groups[Brainpool_P384t1] = ObjectID{group_EcBrainpool,384,2}
	groups[Brainpool_P512r1] = ObjectID{group_EcBrainpool,512,1}
	groups[Brainpool_P512t1] = ObjectID{group_EcBrainpool,512,2}
	
	groups[Complex_2048bit] = ObjectID{group_ComplxGroup,1}
	groups[Complex_4096bit] = ObjectID{group_ComplxGroup,2}
	groups[Complex_8192bit] = ObjectID{group_ComplxGroup,3}
}

type PublicKey struct{
	Group ObjectID
	X,Y *big.Int
	Z []byte
}

type PrivateKey struct{
	Group ObjectID
	Secret *big.Int
}

type Signature struct{
	Sig *big.Int
	Hash []byte
}

