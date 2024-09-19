package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	tlsConf, err := generatesmtlsConfig()
	if err != nil {
		log.Fatal(err)
	}
	tlsConf.ClientAuth = smtls.RequestClientCert
	tlsConf.InsecureSkipVerify = true
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatal(err)
	}
	go connect(ln.Addr())
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	c := smtls.Server(conn, tlsConf, nil)
	if err := c.Handshake(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Received connection from", c.RemoteAddr())
	c.Write([]byte("foo"))
	select {}
}

func connect(addr net.Addr) {
	tlsConf, err := generatesmtlsConfig()
	if err != nil {
		log.Fatal(err)
	}
	tlsConf.InsecureSkipVerify = true
	tlsConf.ClientSessionCache = smtls.NewLRUClientSessionCache(10)
	tlsConf.MinVersion = tls.VersionTLS13
	conn, err := smtls.Dial("tcp", addr.String(), tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte("foobar")); err != nil {
		log.Fatal(err)
	}
	fmt.Println("dialed", conn.RemoteAddr())
}

func generatesmtlsConfig() (*smtls.Config, error) {
	// Generate a new private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// 将 PEM 格式的私钥写入文件
	privKeyFile, err := os.Create("cmd/private_key.pem")
	if err != nil {
		// 处理错误
		return nil, err
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	privKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	}
	err = pem.Encode(privKeyFile, privKeyPEM)
	if err != nil {
		// 处理错误
		return nil, err
	}
	privKeyFile.Close()

	// Create a self-signed certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	// 将自签名证书编码为 PEM 格式
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	// 将 PEM 格式的证书写入文件
	certFile, err := os.Create("cmd/certificate.pem")
	if err != nil {
		// 处理错误
		return nil, err
	}

	err = pem.Encode(certFile, certPEM)
	if err != nil {
		// 处理错误
		return nil, err
	}

	certFile.Close()

	// Create a new TLS certificate with the private key and self-signed certificate
	cert := smtls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
		OCSPStaple:  make([]byte, math.MaxUint16-372),
	}

	// Create a new TLS configuration with the self-signed certificate
	tlsConfig := &smtls.Config{
		Certificates: []smtls.Certificate{cert},
	}
	return tlsConfig, nil
}

func generateTLSConfig() (*tls.Config, error) {
	// Generate a new private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// 将 PEM 格式的私钥写入文件
	privKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		// 处理错误
		return nil, err
	}
	defer privKeyFile.Close()
	privKeyBlock := &pem.Block{Type: "MESSAGE", Bytes: privKey.D.Bytes()}
	err = pem.Encode(privKeyFile, privKeyBlock)
	if err != nil {
		// 处理错误
		return nil, err
	}

	// Create a self-signed certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	// Create a new TLS certificate with the private key and self-signed certificate
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
	}

	// Create a new TLS configuration with the self-signed certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return tlsConfig, nil
}
