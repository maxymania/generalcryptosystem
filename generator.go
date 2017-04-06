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

import "io"
import "math/big"
import "crypto/elliptic"

type ErrorCode uint
const (
	EInvalidGroup = ErrorCode(iota)
	EHeaderTooBig
	EGroupMismatch
)
func (e ErrorCode) Error() string {
	switch e {
	case EInvalidGroup:return "Inavlid group"
	case EHeaderTooBig:return "Header too big"
	case EGroupMismatch:return "Group mismatch"
	}
	return "Unknown error"
}

func generateECKeyPair(curve elliptic.Curve,r io.Reader) (*big.Int,*big.Int,*big.Int,error){
	priv,x,y,e := elliptic.GenerateKey(curve,r)
	return new(big.Int).SetBytes(priv),x,y,e
}
func getCurve(group ObjectID) elliptic.Curve{
	if len(group)<2 { return nil }
	switch group[0] {
	case group_EcFips:
		switch group[1] {
		case 224: return elliptic.P224()
		case 256: return elliptic.P256()
		case 384: return elliptic.P384()
		case 521: return elliptic.P521()
		default: return nil
		}
	case group_EcKoblitz:
		curve := getKoblitz(group[1])
		if curve==nil { return nil }
		return curve
	case group_EcBrainpool:
		return getBrainpool(group)
	}
	return nil
}

func GenerateKeyPair(group ObjectID,r io.Reader) (*PublicKey,*PrivateKey,error) {
	var e error
	
	if len(group)<2 { return nil,nil,EInvalidGroup }
	pub  := new(PublicKey)
	priv := new(PrivateKey)
	pub.Group  = group
	priv.Group = group
	
	if group[0]==group_ModP {
		priv.Secret,pub.X,e  = modpKey(group[1],r)
		if e!=nil { return nil,nil,e }
		pub.Y = new(big.Int).SetUint64(0)
		pub.Z = []byte{}
		return pub,priv,nil
	}
	
	if curve := getCurve(group); curve!=nil {
		priv.Secret,pub.X,pub.Y,e = generateECKeyPair(curve,r)
		if e!=nil { return nil,nil,e }
		pub.Z = []byte{}
		return pub,priv,nil
	}
	
	return nil,nil,EInvalidGroup
}

// Generates the Public Key from the Private Key.
// This is useful, if the user lost his Public Key.
// If the operation is not supported, the method shall return nil.
func (priv *PrivateKey) PublicKey() *PublicKey {
	var e error
	pub := new(PublicKey )
	pub.Group = priv.Group
	if len(priv.Group)<2 { return nil }
	if priv.Group[0]==group_ModP {
		pub.X,e = modpExp(priv.Group[1],priv.Secret)
		if e!=nil { return nil }
		pub.Y = new(big.Int).SetUint64(0)
		pub.Z = []byte{}
		return pub
	}
	
	if curve := getCurve(priv.Group); curve!=nil {
		pub.X,pub.Y = curve.ScalarBaseMult(priv.Secret.Bytes())
		pub.Z = []byte{}
		return pub
	}
	
	return nil
}

