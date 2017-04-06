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
import "hash"
import "math/big"
import "crypto/rand"
import "golang.org/x/crypto/blake2b"
import "crypto/subtle"

type Signer interface {
	io.Writer
	
	Sign() *Signature
}
type Verifier interface {
	io.Writer
	
	Verify() bool
}

type signer struct {
	io.Writer
	h hash.Hash
	k *big.Int
	x *big.Int
}
func Sign(priv *PrivateKey,r io.Reader) (Signer,error) {
	M := new(big.Int).Lsh(priv.Secret,512)
	k,e := rand.Int(r, M)
	if e!=nil { return nil,e }
	k = new(big.Int).Add(k,M)
	var K []byte
	
	if len(priv.Group)<2 { return nil,EInvalidGroup }
	
	if priv.Group[0]==group_ModP {
		Ke,e := modpExp(priv.Group[1],k)
		if e!=nil { return nil,EInvalidGroup }
		K = Ke.Bytes()
	}else  if curve := getCurve(priv.Group); curve!=nil {
		x,y := curve.ScalarBaseMult(k.Bytes())
		K = append(x.Bytes(),y.Bytes()...)
	}else { return nil,EInvalidGroup }
	
	if len(K)>64 {
		sum := blake2b.Sum512(K)
		K = sum[:]
	}
	
	h,_ := blake2b.New512(K)
	
	return &signer{h,h,k,priv.Secret},nil
}
func (s *signer) Sign() *Signature {
	h := s.h.Sum(make([]byte,0,64))
	e := new(big.Int).SetBytes(h)
	xe := new(big.Int).Mul(s.x,e)
	sig := e.Sub(s.k,xe)
	return &Signature{sig,h}
}

type verifier struct {
	io.Writer
	h hash.Hash
	should []byte
}
func Verify(pub *PublicKey, sig *Signature) (Verifier,error) {
	if len(pub.Group)<2 { return nil,EInvalidGroup }
	var K []byte
	if pub.Group[0]==group_ModP {
		g,ok := linearGroups[pub.Group[1]]
		if !ok { return nil,EInvalidGroup }
		gs := new(big.Int).Exp(g.G,sig.Sig,g.P)
		ye := new(big.Int).Exp(pub.X,new(big.Int).SetBytes(sig.Hash),g.P)
		gsye := new(big.Int).Mul(gs,ye)
		Ke := gs.Mod(gsye,g.P)
		K = Ke.Bytes()
	}else  if curve := getCurve(pub.Group); curve!=nil {
		gsx,gsy := curve.ScalarBaseMult(sig.Sig.Bytes())
		yex,yey := curve.ScalarMult(pub.X,pub.Y,sig.Hash)
		x,y := curve.Add(gsx,gsy,yex,yey)
		K = append(x.Bytes(),y.Bytes()...)
	}else { return nil,EInvalidGroup }
	
	if len(K)>64 {
		sum := blake2b.Sum512(K)
		K = sum[:]
	}
	
	h,_ := blake2b.New512(K)
	
	return &verifier{h,h,sig.Hash},nil
}
func (v *verifier) Verify() bool {
	h := v.h.Sum(make([]byte,0,64))
	return subtle.ConstantTimeCompare(h,v.should) == 1
}


