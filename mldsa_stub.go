//go:build !go1.27

package certinfo

import "crypto/x509"

var x509MLDSA = x509.PublicKeyAlgorithm(-1)

type mldsaPublicKey struct{}

func (*mldsaPublicKey) Parameters() parameters {
	return parameters{}
}

func (*mldsaPublicKey) Bytes() []byte {
	return []byte{}
}

type parameters struct{}

func (p parameters) String() string {
	return ""
}

func (p parameters) PublicKeySize() int {
	return 0
}
