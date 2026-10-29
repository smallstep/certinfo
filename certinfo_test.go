package certinfo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math"
	"math/big"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type InputType int

const (
	tCertificate InputType = iota
	tCertificateRequest
)

// Compares a PEM-encoded certificate to a reference file.
func testPair(t *testing.T, certFile, refFile string, inputType InputType) {
	t.Helper()

	// Read and parse the certificate
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(pemData)
	if block == nil || len(rest) > 0 {
		t.Fatal("Certificate decoding error")
	}
	var result string
	switch inputType {
	case tCertificate:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateText(cert)
		if err != nil {
			t.Fatal(err)
		}
	case tCertificateRequest:
		cert, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateRequestText(cert)
		if err != nil {
			t.Fatal(err)
		}
	}
	resultData := []byte(result)

	// Read the reference output
	refData, err := os.ReadFile(refFile)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a diff and check if it's empty; if not, report error
	if diff := cmp.Diff(refData, resultData); diff != "" {
		t.Logf("'%s' did not match reference '%s'\n", certFile, refFile)
		t.Errorf("Diff follows:\n%s\n", diff)
	}
}

// Compares a PEM-encoded certificate to a reference file.
func testPairShort(t *testing.T, certFile, refFile string, inputType InputType) {
	t.Helper()

	// Read and parse the certificate
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(pemData)
	if block == nil || len(rest) > 0 {
		t.Fatal("Certificate decoding error")
	}
	var result string
	switch inputType {
	case tCertificate:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateShortText(cert)
		if err != nil {
			t.Fatal(err)
		}
	case tCertificateRequest:
		cert, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		result, err = CertificateRequestShortText(cert)
		if err != nil {
			t.Fatal(err)
		}
	}
	resultData := []byte(result)

	// Read the reference output
	refData, err := os.ReadFile(refFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resultData, refData) {
		t.Logf("'%s' did not match reference '%s'\n", certFile, refFile)
		t.Errorf("Dump follows:\n%s\n", result)
	}
}

// Test the root CA certificate
func TestCertInfoRoot(t *testing.T) {
	testPair(t, "test_certs/root1.cert.pem", "test_certs/root1.cert.text", tCertificate)
	testPair(t, "test_certs/root1.csr.pem", "test_certs/root1.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/root1.cert.pem", "test_certs/root1.cert.short", tCertificate)
	testPairShort(t, "test_certs/root1.csr.pem", "test_certs/root1.csr.short", tCertificateRequest)
}

// Test the leaf (user) RSA certificate
func TestCertInfoLeaf1(t *testing.T) {
	testPair(t, "test_certs/leaf1.cert.pem", "test_certs/leaf1.cert.text", tCertificate)
	testPair(t, "test_certs/leaf1.csr.pem", "test_certs/leaf1.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf1.cert.pem", "test_certs/leaf1.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf1.csr.pem", "test_certs/leaf1.csr.short", tCertificateRequest)
}

// Test the leaf (user) DSA certificate
func TestCertInfoLeaf2(t *testing.T) {
	testPair(t, "test_certs/leaf2.cert.pem", "test_certs/leaf2.cert.text", tCertificate)
	testPair(t, "test_certs/leaf2.csr.pem", "test_certs/leaf2.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf2.cert.pem", "test_certs/leaf2.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf2.csr.pem", "test_certs/leaf2.csr.short", tCertificateRequest)
}

// Test the leaf (user) ECDSA certificate
func TestCertInfoLeaf3(t *testing.T) {
	testPair(t, "test_certs/leaf3.cert.pem", "test_certs/leaf3.cert.text", tCertificate)
	testPair(t, "test_certs/leaf3.csr.pem", "test_certs/leaf3.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf3.cert.pem", "test_certs/leaf3.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf3.csr.pem", "test_certs/leaf3.csr.short", tCertificateRequest)
}

// Test the leaf (user) with multiple sans
func TestCertInfoLeaf4(t *testing.T) {
	testPair(t, "test_certs/leaf4.cert.pem", "test_certs/leaf4.cert.text", tCertificate)
	testPair(t, "test_certs/leaf4.csr.pem", "test_certs/leaf4.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf4.cert.pem", "test_certs/leaf4.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf4.csr.pem", "test_certs/leaf4.csr.short", tCertificateRequest)
}

func TestCertInfoLeaf5(t *testing.T) {
	testPair(t, "test_certs/leaf5.cert.pem", "test_certs/leaf5.cert.text", tCertificate)
	testPair(t, "test_certs/leaf5.csr.pem", "test_certs/leaf5.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf5.cert.pem", "test_certs/leaf5.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf5.csr.pem", "test_certs/leaf5.csr.short", tCertificateRequest)
}

func TestCertInfoLeaf6(t *testing.T) {
	testPair(t, "test_certs/leaf6.cert.pem", "test_certs/leaf6.cert.text", tCertificate)
	testPair(t, "test_certs/leaf6.csr.pem", "test_certs/leaf6.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/leaf6.cert.pem", "test_certs/leaf6.cert.short", tCertificate)
	testPairShort(t, "test_certs/leaf6.csr.pem", "test_certs/leaf6.csr.short", tCertificateRequest)
}

func TestCsrInfoWackyExtensions(t *testing.T) {
	testPair(t, "test_certs/x509WackyExtensions.pem", "test_certs/x509WackyExtensions.text", tCertificateRequest)
}

func TestNoCN(t *testing.T) {
	testPair(t, "test_certs/noCN.csr", "test_certs/noCN.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/noCN.csr", "test_certs/noCN.csr.text.short", tCertificateRequest)
}

func TestSigstoreCertInfo(t *testing.T) {
	testPair(t, "test_certs/sigstore1.cert.pem", "test_certs/sigstore1.cert.text", tCertificate)
	testPair(t, "test_certs/sigstore2.cert.pem", "test_certs/sigstore2.cert.text", tCertificate)
}

func TestUnknownCrypto(t *testing.T) {
	if x509MLDSA != -1 {
		// Valid ML-DSA certificates will be different on Go < 1.27
		testPair(t, "test_certs/ML-DSA-44.crt", "test_certs/ML-DSA-44.crt.text", tCertificate)
		testPair(t, "test_certs/ML-DSA-65.crt", "test_certs/ML-DSA-65.crt.text", tCertificate)
		testPair(t, "test_certs/ML-DSA-87.crt", "test_certs/ML-DSA-87.crt.text", tCertificate)
		testPairShort(t, "test_certs/ML-DSA-44.crt", "test_certs/ML-DSA-44.crt.text.short", tCertificate)
		testPairShort(t, "test_certs/ML-DSA-65.crt", "test_certs/ML-DSA-65.crt.text.short", tCertificate)
		testPairShort(t, "test_certs/ML-DSA-87.crt", "test_certs/ML-DSA-87.crt.text.short", tCertificate)
	}

	testPair(t, "test_certs/digicert_mldsa-44.csr", "test_certs/digicert_mldsa-44.csr.text", tCertificateRequest)
	testPair(t, "test_certs/digicert_mldsa-65.csr", "test_certs/digicert_mldsa-65.csr.text", tCertificateRequest)
	testPair(t, "test_certs/digicert_mldsa-87.csr", "test_certs/digicert_mldsa-87.csr.text", tCertificateRequest)
	testPairShort(t, "test_certs/digicert_mldsa-44.csr", "test_certs/digicert_mldsa-44.csr.text.short", tCertificateRequest)
	testPairShort(t, "test_certs/digicert_mldsa-65.csr", "test_certs/digicert_mldsa-65.csr.text.short", tCertificateRequest)
	testPairShort(t, "test_certs/digicert_mldsa-87.csr", "test_certs/digicert_mldsa-87.csr.text.short", tCertificateRequest)
}

func Test_mustInt64(t *testing.T) {
	if v := mustInt64(0); v != 0 {
		t.Errorf("expected 0; got %d", v)
	}

	if v := mustInt64(math.MaxInt64); v != math.MaxInt64 {
		t.Errorf("expected 9223372036854775807; got %d", v)
	}

	if v := mustInt64(42); v != 42 {
		t.Errorf("expected 42; got %d", v)
	}

	mustPanic(t, func() { mustInt64(math.MaxInt64 + 1) })
}

func mustPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			_, file, line, _ := runtime.Caller(2)
			t.Errorf("expected function call at %s:%d to panic", file, line)
		}
	}()

	f()
}

// TestCertificateText_stepManagedDeviceEnrolledAt checks the Step Managed
// Device extension with the optional enrolledAt field, with and without it,
// and with a later appended field. Later fields are context-tagged IMPLICIT
// OPTIONAL elements and readers ignore trailing elements.
func TestCertificateText_stepManagedDeviceEnrolledAt(t *testing.T) {
	const deviceID = "2b2f4e1c-0000-4a1f-9d1e-8a7d2e0f1111"
	enrolledAt := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	render := func(t *testing.T, value []byte) string {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "enrollment-test"},
			NotBefore:    time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC),
			ExtraExtensions: []pkix.Extension{
				{Id: oidStepManagedDevice, Value: value},
			},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		got, err := CertificateText(cert)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	const (
		header   = "            X509v3 Step Managed Device:\n"
		idLine   = "                DeviceID: " + deviceID + "\n"
		timeLine = "                EnrolledAt: 2026-10-28T12:00:00Z\n"
	)

	t.Run("device ID only", func(t *testing.T) {
		value, err := asn1.Marshal(struct {
			DeviceID string `asn1:"printable"`
		}{deviceID})
		if err != nil {
			t.Fatal(err)
		}
		got := render(t, value)
		if !strings.Contains(got, header+idLine) {
			t.Errorf("output does not contain the device ID block:\n%s", got)
		}
		if strings.Contains(got, "EnrolledAt") {
			t.Errorf("output must not contain EnrolledAt:\n%s", got)
		}
	})

	t.Run("enrolled", func(t *testing.T) {
		value, err := asn1.Marshal(struct {
			DeviceID   string    `asn1:"printable"`
			EnrolledAt time.Time `asn1:"generalized"`
		}{deviceID, enrolledAt})
		if err != nil {
			t.Fatal(err)
		}
		got := render(t, value)
		if !strings.Contains(got, header+idLine+timeLine) {
			t.Errorf("output does not contain the enrolled block:\n%s", got)
		}
	})

	t.Run("enrolled with a later appended field", func(t *testing.T) {
		value, err := asn1.Marshal(struct {
			DeviceID   string    `asn1:"printable"`
			EnrolledAt time.Time `asn1:"generalized"`
			Method     string    `asn1:"tag:0,optional,utf8"`
		}{deviceID, enrolledAt, "agent"})
		if err != nil {
			t.Fatal(err)
		}
		got := render(t, value)
		if !strings.Contains(got, header+idLine+timeLine) {
			t.Errorf("output does not contain the enrolled block:\n%s", got)
		}
	})
}
