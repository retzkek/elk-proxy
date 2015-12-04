package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
)

var authorizedCNs = []string{"Kevin Retzke 3130"}

func main() {
	proxy := NewProxyServer("localhost", "8443", "http://localhost:9200")
	http.HandleFunc("/", proxy.handler)
	log.Printf("About to listen on 8443. Go to https://127.0.0.1:8443/")
	srv := http.Server{Addr: ":8443"}

	f, err := os.Open("certs/ca-bundle.crt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(buf.Bytes()); !ok {
		log.Fatal(err)
	}

	srv.TLSConfig = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs: pool}
	err = srv.ListenAndServeTLS("certs/cert.pem", "certs/key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
