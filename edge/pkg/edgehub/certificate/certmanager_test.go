package certificate

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	keysize = 768
	tmpdir  = "../../../../_tmp/testing"
)

// miniCa is a small ca for testcases capable of creating a self signed root certificate,
// sign client and server certs, and create a readily configured httptest.Server
type miniCa struct {
	serialNumber *big.Int
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
}

// newCA initializes the CA
func newCA(t *testing.T) *miniCa {
	privateKey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		t.Fatalf("Failed to create ca key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Issuer: pkix.Name{
			CommonName: "testca",
		},
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	caCert := &x509.Certificate{Raw: cert, PublicKey: &privateKey.PublicKey}

	return &miniCa{serialNumber: template.SerialNumber, caCert: caCert, caKey: privateKey}
}

// createServerCert creates and signs a server side certificate
func (ca *miniCa) createServerCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: ca.serialNumber.Add(ca.serialNumber, big.NewInt(1)),
		Issuer: pkix.Name{
			CommonName: "test server",
		},
		IsCA:        false,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, ca.caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCert := &x509.Certificate{Raw: cert, PublicKey: &privateKey.PublicKey}
	return serverCert, privateKey
}

// createClientCert creates and signs a client side certificate
func (ca *miniCa) createClientCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keysize)
	if err != nil {
		t.Fatal(err)

	}
	template := &x509.Certificate{
		SerialNumber: ca.serialNumber.Add(ca.serialNumber, big.NewInt(1)),
		Issuer: pkix.Name{
			CommonName: "client",
		},
		IsCA:        false,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, ca.caKey)
	if err != nil {
		t.Fatal(err)

	}
	serverCert := &x509.Certificate{Raw: cert, PublicKey: &privateKey.PublicKey}
	return serverCert, privateKey
}

// createTlsConfig creates a new TLS server config using a new server certificate
func (ca *miniCa) createTlsConfig(t *testing.T) (*tls.Config, string) {
	cert, key := ca.createServerCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	config := &tls.Config{
		Rand:         rand.Reader,
		Time:         time.Now,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		RootCAs:      pool,
	}

	builder := strings.Builder{}
	pem.Encode(&builder, &pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})
	caCert := builder.String()

	return config, caCert
}

// createServer creates a httptest.Server using a new server certificate
func (ca *miniCa) createServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	server := httptest.NewUnstartedServer(handler)
	tlsConfig, caCert := ca.createTlsConfig(t)
	server.TLS = tlsConfig
	server.StartTLS()
	return server, caCert
}

// writeCertificate writes a certificate as PEM file
func writeCertificate(t *testing.T, cert *x509.Certificate, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create file %q: %v", filename, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	if err := pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatalf("Failed to write certificate %q: %v", filename, err)
	}
}

func writeKey(t *testing.T, privateKey crypto.PrivateKey, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create file %q: %v", filename, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	var keydata []byte
	var header string

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		keydata = x509.MarshalPKCS1PrivateKey(k)
		header = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		keydata, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		header = "EC PRIVATE KEY"
	}
	if err := pem.Encode(writer, &pem.Block{Type: header, Bytes: keydata}); err != nil {
		t.Fatalf("Failed to write certificate %q: %v", filename, err)
	}
}

func setup(t *testing.T) {
	if err := os.RemoveAll(tmpdir); err != nil {
		t.Fatalf("Failed to remove directory %q: %v", tmpdir, err)
	}

	if err := os.MkdirAll(tmpdir, 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}
}
func TestExternalCertReceiver(t *testing.T) {
	ca := newCA(t)
	setup(t)
	writeCertificate(t, ca.caCert, tmpdir+"/ca.crt")
	clientCert, clientKey := ca.createClientCert(t)
	writeCertificate(t, clientCert, tmpdir+"/client.crt")
	writeKey(t, clientKey, tmpdir+"/client.key")

	ecr := ExternalCertificateRetriever{
		caFile:   tmpdir + "/ca.crt",
		certFile: tmpdir + "/client.crt",
		keyFile:  tmpdir + "/client.key",
		now:      time.Now,
	}
	if err := ecr.RetrieveCertificate(); err != nil {
		t.Fatalf("Failed to retrieve certificates: %v", err)
	}
}

func TestNotExistingCerts(t *testing.T) {
	setup(t)
	ecr := ExternalCertificateRetriever{
		caFile:   tmpdir + "/ca.crt",
		certFile: tmpdir + "/client.crt",
		keyFile:  tmpdir + "/client.key",
		now:      time.Now,
	}
	if err := ecr.RetrieveCertificate(); err == nil {
		t.Fatalf("Expected an error with not existing certificates")
	}

}
