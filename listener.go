package main

import (
	"crypto/tls"
	//"crypto/x509"
	"fmt"
	//"io/ioutil"
	"net"
	"sync"
	"time"
	"flag"
)

var cipher_suite = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
}

var certfile = flag.String("certfile", "", "certfile for server")
var keyfile = flag.String("keyfile", "", "keyfile")

/*
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
*/

func tlsConfig(certfile, keyfile string) (*tls.Config, error) {
	var (
		cert    tls.Certificate
		err     error
		tlsConf *tls.Config
	)
	tlsConf = &tls.Config{}

	cert, err = tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}

	tlsConf.Certificates = []tls.Certificate{cert}
	tlsConf.NameToCertificate = make(map[string]*tls.Certificate)
	tlsConf.NameToCertificate["default"] = &cert
	tlsConf.CipherSuites = cipher_suite
	tlsConf.PreferServerCipherSuites = true
	return tlsConf, nil

}

func handleConnection(conn net.Conn, stopChan chan bool, wg sync.WaitGroup) {
	defer func() {
		conn.Close()
		wg.Done()

	}()
	var (
		e      error
		buffer []byte
		n      int
	)
	buffer = make([]byte, 16384)

	running := true
	for running {
		e = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		select {
		case _, running = <-stopChan:
		default:
			n, e = conn.Read(buffer)
			if e != nil {
				if neterr, ok := e.(net.Error); ok && neterr.Timeout() {
					fmt.Println("kjdkfaj\n")
				} else {
					running = false
				}
			}
			if n != 0 {
				fmt.Printf("%s\n")
			}

		}
	}

}

func main() {
	var (
		raw_listener net.Listener
		tls_listener net.Listener
		err          error
		//wg           sync.WaitGroup
		t        *net.TCPAddr
		tls_conf *tls.Config
	)
	flag.Parse()
	t, _ = net.ResolveTCPAddr("tcp", "0.0.0.0:5567")
	tls_listener, err = net.ListenTCP("tcp", t)
	if err != nil {
		panic(err)
	}
	tls_conf, err = tlsConfig(*certfile, *keyfile)
	if err != nil {
		panic(err)
	}
	tls_listener = tls.NewListener(tls_listener, tls_conf)

	t, _ = net.ResolveTCPAddr("tcp", "0.0.0.0:5568")
	raw_listener, err = net.ListenTCP("tcp", t)
	errChan := make(chan error)
	stopChan := make(chan bool)
	defer tls_listener.Close()
	defer raw_listener.Close()

	manage_listener := func(l net.Listener) {
		var (
			conn net.Conn
			e    error
			wg   sync.WaitGroup
		)
		defer func() {
			l.Close()
			wg.Wait()

		}()
		for {
			if conn, e = l.Accept(); e != nil {
				if e.(net.Error).Temporary() {
					errChan <- fmt.Errorf("TCP Accept failed: %s", e)
					continue
				} else {
					break
				}
			}
			wg.Add(1)
			go handleConnection(conn, stopChan, wg)
		}

	}
	go manage_listener(tls_listener)
	go manage_listener(raw_listener)

}
