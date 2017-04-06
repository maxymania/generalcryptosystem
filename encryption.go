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
import "bytes"
import "math/big"
import "crypto/elliptic"
import "crypto/cipher"
import "crypto/rand"
import "golang.org/x/crypto/blake2b"
import "golang.org/x/crypto/twofish"
import "encoding/asn1"
import "encoding/binary"

type encrypter struct{
	dest io.Writer
	clos io.Closer
	buf bytes.Buffer
	mode cipher.BlockMode
	fb []byte
}
func (e *encrypter) get(i int) []byte {
	if cap(e.fb) < i { e.fb = make([]byte,0,i) }
	return e.fb[:i]
}
func (e *encrypter) Write(p []byte) (n int, err error){
	n,err = e.buf.Write(p)
	e.push()
	return
}
func (e *encrypter) Close() error {
	e.push()
	pad := padBlock(e.buf.Len(),e.mode.BlockSize())
	e.buf.Write(pad)
	dest := e.get(e.buf.Len())
	e.mode.CryptBlocks(dest,e.buf.Bytes())
	e.dest.Write(dest)
	if e.clos==nil { return nil }
	return e.clos.Close()
}
func (e *encrypter) push(){
	bz := e.mode.BlockSize()
	l := e.buf.Len()
	l -= l%bz
	if l==0 { return }
	dest := e.get(l)
	e.mode.CryptBlocks(dest,e.buf.Next(l))
	e.dest.Write(dest)
}
func Encrypt(pub *PublicKey, r io.Reader, dest io.Writer) (io.WriteCloser,error) {
	peer := new(PublicKey)
	peer.Group = pub.Group
	var K []byte
	if pub.Group[0]==group_ModP {
		g,ok := linearGroups[pub.Group[1]]
		if !ok { return nil,EInvalidGroup }
		t,T,e := modpKey(pub.Group[1],r)
		if e!=nil { return nil,e }
		peer.X = T
		peer.Y = new(big.Int).SetUint64(0)
		peer.Z = []byte{}
		Ke := new(big.Int).Exp(pub.X,t,g.P)
		K = Ke.Bytes()
	}else  if curve := getCurve(pub.Group); curve!=nil {
		var Secret []byte
		var e error
		Secret,peer.X,peer.Y,e = elliptic.GenerateKey(curve,r)
		if e!=nil { return nil,e }
		peer.Z = []byte{}
		x,y := curve.ScalarMult(pub.X,pub.Y,Secret)
		K = append(x.Bytes(),y.Bytes()...)
	}else { return nil,EInvalidGroup }
	
	var iv [16]byte
	key := blake2b.Sum256(K)
	c,_ := twofish.NewCipher(key[:])
	rand.Read(iv[:])
	mode := cipher.NewCBCEncrypter(c,iv[:])
	cl,ok := dest.(io.Closer)
	if !ok { cl=nil }
	
	b,e := asn1.Marshal(*peer)
	if e!=nil { return nil,e }
	
	var bl uint32
	bl = uint32(len(b))
	e = binary.Write(dest,binary.BigEndian,bl)
	if e!=nil { return nil,e }
	_,e = dest.Write(b)
	if e!=nil { return nil,e }
	_,e = dest.Write(iv[:])
	if e!=nil { return nil,e }
	
	enc := new(encrypter)
	enc.dest = dest
	enc.clos = cl
	enc.mode = mode
	return enc,nil
}

type decrypter struct{
	src  io.Reader
	ctb  bytes.Buffer
	dec  bytes.Buffer
	user bytes.Buffer
	mode cipher.BlockMode
	fb []byte
	e    error
}
func (e *decrypter) get(i int) []byte {
	if cap(e.fb) < i { e.fb = make([]byte,i) }
	return e.fb[:i]
}
func (d *decrypter) fill() {
	n,e := d.src.Read(d.fb)
	if n>0 { d.ctb.Write(d.fb[:n]) }
	if n<1 || e==io.EOF {
		d.e = io.EOF
		return
	}
}
func (d *decrypter) decrypt() {
	bz := d.mode.BlockSize()
	l := d.ctb.Len()
	l -= l%bz
	if l==0 { return }
	dest := d.get(l)
	d.mode.CryptBlocks(dest,d.ctb.Next(l))
	d.dec.Write(dest)
}
func (d *decrypter) unpad() {
	bz := d.mode.BlockSize()
	l := d.dec.Len()
	lmb := l%bz
	if lmb>0 {
		l -= lmb
	}else{
		l -= bz
	}
	if l==0 { return }
	d.user.Write(d.dec.Next(l))
}
func (d *decrypter) refill() {
	if d.e!=nil { return }
	d.fill()
	d.decrypt()
	d.unpad()
	if d.e!=nil {
		bz := d.mode.BlockSize()
		l := d.dec.Len()
		if l==bz {
			d.user.Write(unpadBlock(d.dec.Bytes()))
		}
	}
}
func (d *decrypter) Read(p []byte) (n int, err error) {
	d.refill()
	n,_ = d.user.Read(p)
	if d.user.Len() == 0 { err = d.e }
	return
}


func Decrypt(priv *PrivateKey, src io.Reader) (io.Reader,error) {
	var hl uint32
	var iv [16]byte
	e := binary.Read(src,binary.BigEndian,&hl)
	if e!=nil { return nil,e }
	if hl > (1<<20) { return nil,EHeaderTooBig }
	b := make([]byte,int(hl))
	_,e = io.ReadFull(src,b)
	if e!=nil { return nil,e }
	_,e = io.ReadFull(src,iv[:])
	if e!=nil { return nil,e }
	peer := new(PublicKey)
	_,e = asn1.Unmarshal(b,peer)
	if e!=nil { return nil,e }
	
	if len(peer.Group)!=len(priv.Group) { return nil,EGroupMismatch }
	for i,grp := range peer.Group {
		if priv.Group[i]!=grp { return nil,EGroupMismatch }
	}
	
	var K []byte
	if len(priv.Group)<2 { return nil,EInvalidGroup }
	if priv.Group[0]==group_ModP {
		g,ok := linearGroups[priv.Group[1]]
		if !ok { return nil,EInvalidGroup }
		Ke := new(big.Int).Exp(peer.X,priv.Secret,g.P)
		K = Ke.Bytes()
	}else if curve := getCurve(priv.Group); curve!=nil {
		x,y := curve.ScalarMult(peer.X,peer.Y,priv.Secret.Bytes())
		K = append(x.Bytes(),y.Bytes()...)
	}else { return nil,EInvalidGroup }
	
	
	key := blake2b.Sum256(K)
	c,_ := twofish.NewCipher(key[:])
	mode := cipher.NewCBCDecrypter(c,iv[:])
	
	dec := new(decrypter)
	
	//dec.ctb = new(bytes.Buffer)
	//dec.dec = new(bytes.Buffer)
	//dec.user = new(bytes.Buffer)
	
	dec.src  = src
	dec.mode = mode
	dec.fb   = make([]byte,1<<12)
	
	return dec,nil
}


