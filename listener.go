package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
)

func certPoolFromFile(pemfile string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	data, err := ioutil.ReadFile(pemfile)
	if err != nil {
		return nil, err
	}
	if roots.AppendCertsFromPEM(data) {
		return roots, nil
	}
	return nil, fmt.Errorf("No PEM encoded certificates found in: %s\n", pemfile)
}

func tlsConfig(certfile, keyfile, cafile string) (*tls.Config, error) { 
	var (
		cert tls.Certificate
		err error
	tlsConf *tls.Config
		
	)
	tlsConf = &tls.Config{}

		cert, err = tls.LoadX509KeyPair(tomlConf.CertFile, tomlConf.KeyFile)
		if err != nil {
			return nil, err
		}

		tlsConf.Certificates = []tls.Certificate{cert}
		tlsConf.NameToCertificate = make(map[string]*tls.Certificate)
		tlsConf.NameToCertificate["default"] = &cert
		tlsConf.RootCAs, err = certPoolFromFile(cafile); err != nil {
			return nil, err
		}
		


}


func main() {
}


