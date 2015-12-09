package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

// Read access (GET commands) is allowed to all

// Write access (POST commands) is allowed to users with the folling CNs:
var authorizedWriteCNs = []string{"Kevin Retzke 3130"}

// Admin access (DELETE commands, access to  '/_cat/*) is allowed to users with the folling CNs:
var authorizedAdminCNs = []string{"Kevin Retzke 3130"}

func authorizedCN(certs []*x509.Certificate, cns []string) (bool, string) {
	for _, cert := range certs {
		for _, cn := range cns {
			if cert.Subject.CommonName == cn {
				return true, cn
			}
		}
	}
	return false, ""
}

type ProxyServer struct {
	proxy *httputil.ReverseProxy
}

func NewProxyServer(target_url string) *ProxyServer {
	t, err := url.Parse(target_url)
	if err != nil {
		log.Fatal(err)
	}
	return &ProxyServer{proxy: httputil.NewSingleHostReverseProxy(t)}
}

func (p *ProxyServer) ServeRead(w http.ResponseWriter, req *http.Request) {
	p.proxy.ServeHTTP(w, req)
}

func (p *ProxyServer) ServeWrite(w http.ResponseWriter, req *http.Request) {
	if auth, _ := authorizedCN(req.TLS.PeerCertificates, authorizedWriteCNs); auth {
		p.proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

func (p *ProxyServer) ServeAdmin(w http.ResponseWriter, req *http.Request) {
	if auth, _ := authorizedCN(req.TLS.PeerCertificates, authorizedAdminCNs); auth {
		p.proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

func main() {
	r := mux.NewRouter()

	proxy := NewProxyServer("http://localhost:9200/")
	// Admin
	r.PathPrefix("/_cat").Methods("GET").HandlerFunc(proxy.ServeAdmin)
	r.PathPrefix("/").Methods("DELETE").HandlerFunc(proxy.ServeAdmin)

	// Write
	r.PathPrefix("/").Methods("POST").HandlerFunc(proxy.ServeWrite)

	// Read
	r.PathPrefix("/").Methods("GET").HandlerFunc(proxy.ServeRead)

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
	http.Handle("/", r)

	srv.TLSConfig = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs: pool}
	err = srv.ListenAndServeTLS("certs/cert.pem", "certs/key.pem")
	if err != nil {
		log.Fatal(err)
	}

}
