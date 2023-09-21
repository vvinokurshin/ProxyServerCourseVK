package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"
)

func CreateCert(dnsNames []string, parent *x509.Certificate, parentKey crypto.PrivateKey, hoursValid int) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Sample MITM proxy"},
		},
		DNSNames:  dnsNames,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Duration(hoursValid) * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, parentKey)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return []byte{}, []byte{}, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemCert == nil {
		return []byte{}, []byte{}, err
	}

	return pemCert, pemKey, nil
}

func loadX509KeyPair(certFile, keyFile string) (cert *x509.Certificate, key any, err error) {
	cf, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	kf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(cf)
	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(kf)
	key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

type mitmProxy struct {
	CaCert *x509.Certificate
	CaKey  any
}

func CreateMitmProxy(caCertFile, caKeyFile string) (*mitmProxy, error) {
	caCert, caKey, err := loadX509KeyPair(caCertFile, caKeyFile)
	if err != nil {
		return nil, err
	}

	return &mitmProxy{
		CaCert: caCert,
		CaKey:  caKey,
	}, nil
}
