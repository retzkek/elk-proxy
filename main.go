package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

var authorizedCNs = []string{"Kevin Retzke 3130"}

func authorizedCN(certs []*x509.Certificate) (bool, string) {
	for _, cert := range certs {
		for _, cn := range authorizedCNs {
			if cert.Subject.CommonName == cn {
				return true, cn
			}
		}
	}
	return false, ""
}

type ProxyServer struct {
	Address string
	Port    string

	proxy *httputil.ReverseProxy
}

func NewProxyServer(address, port, target_url string) *ProxyServer {
	t, err := url.Parse(target_url)
	if err != nil {
		log.Fatal(err)
	}
	return &ProxyServer{Address: address,
		Port:  port,
		proxy: httputil.NewSingleHostReverseProxy(t),
	}
}

func (p *ProxyServer) handler(w http.ResponseWriter, req *http.Request) {
	if auth, _ := authorizedCN(req.TLS.PeerCertificates); auth {
		p.proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

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
