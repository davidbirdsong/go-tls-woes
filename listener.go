package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
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

func handleConnection(conn net.Conn, stopChan chan bool, wg *sync.WaitGroup) {
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
					continue
				} else {
					running = false
				}
			}
		}
	}

}

func main() {
	var (
		raw_listener net.Listener
		tls_listener net.Listener
		err          error
		wlist        sync.WaitGroup
		t            *net.TCPAddr
		tls_conf     *tls.Config
	)
	flag.Parse()
	t, _ = net.ResolveTCPAddr("tcp", "0.0.0.0:5114")
	tls_listener, err = net.ListenTCP("tcp", t)
	if err != nil {
		panic(err)
	}
	tls_conf, err = tlsConfig(*certfile, *keyfile)
	if err != nil {
		panic(err)
	}
	tls_listener = tls.NewListener(tls_listener, tls_conf)

	t, _ = net.ResolveTCPAddr("tcp", "0.0.0.0:5566")
	raw_listener, err = net.ListenTCP("tcp", t)
	stopChan := make(chan bool)
	shutdown := make(chan bool)

	manage_listener := func(l net.Listener) {
		var (
			conn net.Conn
			e    error
		)
		defer wlist.Done()
		for {
			if conn, e = l.Accept(); e != nil {
				if e.(net.Error).Temporary() {
					fmt.Printf("TCP Accept failed: %s", e)
					continue
				} else {
					fmt.Printf("TCP badness %s\n", e)
					break
				}
			}
			wlist.Add(1)
			go handleConnection(conn, stopChan, &wlist)
		}

	}
	wlist.Add(1)
	go manage_listener(tls_listener)
	wlist.Add(1)
	go manage_listener(raw_listener)

	go func() {
		chSignal := make(chan os.Signal, 1)
		signal.Notify(chSignal, syscall.SIGINT)
		<-chSignal
		close(shutdown)
		close(stopChan)

		tls_listener.Close()
		raw_listener.Close()
	}()
	wlist.Wait()

}
