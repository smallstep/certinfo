//go:build go1.27

package certinfo

import (
	"crypto/mldsa"
	"crypto/x509"
)

var x509MLDSA = x509.MLDSA

type mldsaPublicKey = mldsa.PublicKey
