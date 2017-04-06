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

import "github.com/ebfe/brainpool"
import "crypto/elliptic"

func getBrainpool(id ObjectID) elliptic.Curve {
	if len(id)<3 { return nil }
	type temp struct{ R,T func() elliptic.Curve }
	var t temp
	switch id[1] {
	case 160:t = temp{brainpool.P160r1,brainpool.P160t1}
	case 192:t = temp{brainpool.P192r1,brainpool.P192t1}
	case 224:t = temp{brainpool.P224r1,brainpool.P224t1}
	case 256:t = temp{brainpool.P256r1,brainpool.P256t1}
	case 320:t = temp{brainpool.P320r1,brainpool.P320t1}
	case 384:t = temp{brainpool.P384r1,brainpool.P384t1}
	case 512:t = temp{brainpool.P512r1,brainpool.P512t1}
	default: return nil
	}
	switch id[2] {
	case 1: return t.R()
	case 2: return t.T()
	}
	return nil
}

