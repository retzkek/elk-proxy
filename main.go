package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

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
	Config *config
	Proxy  *httputil.ReverseProxy
}

func NewProxyServer(config *config) *ProxyServer {
	var p ProxyServer
	p.Config = config
	t, err := url.Parse(p.Config.Server.Proxy)
	if err != nil {
		log.Fatal(err)
	}
	p.Proxy = httputil.NewSingleHostReverseProxy(t)
	return &p
}

func (p *ProxyServer) ServeRead(w http.ResponseWriter, req *http.Request) {
	p.Proxy.ServeHTTP(w, req)
}

func (p *ProxyServer) ServeWrite(w http.ResponseWriter, req *http.Request) {
	if auth, _ := authorizedCN(req.TLS.PeerCertificates, p.Config.Global.WriteCerts); auth {
		p.Proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

func (p *ProxyServer) ServeAdmin(w http.ResponseWriter, req *http.Request) {
	if auth, _ := authorizedCN(req.TLS.PeerCertificates, p.Config.Global.AdminCerts); auth {
		p.Proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

func main() {
	log.Println("Reading config file test.toml")
	config, err := ReadConfig("test.toml")
	if err != nil {
		log.Fatal(err)
	}
	j, err := json.MarshalIndent(config, "..", "\t")
	if err != nil {
		log.Printf("Config: %v", config)
	} else {
		log.Printf("Config: %s", j)
	}

	r := mux.NewRouter()

	proxy := NewProxyServer(config)
	// Admin
	r.PathPrefix("/_cat").Methods("GET").HandlerFunc(proxy.ServeAdmin)
	r.PathPrefix("/").Methods("DELETE").HandlerFunc(proxy.ServeAdmin)

	// Write
	r.PathPrefix("/").Methods("POST").HandlerFunc(proxy.ServeWrite)

	// Read
	r.PathPrefix("/").Methods("GET").HandlerFunc(proxy.ServeRead)

	log.Printf("About to listen on %s", config.Server.Listen)
	srv := http.Server{Addr: config.Server.Listen}

	pool := x509.NewCertPool()
	for _, ca := range config.Server.CaCerts {
		f, err := os.Open(ca)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(f); err != nil {
			log.Fatal(err)
		}
		if ok := pool.AppendCertsFromPEM(buf.Bytes()); !ok {
			log.Fatal(err)
		}
	}
	http.Handle("/", r)

	srv.TLSConfig = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs: pool}
	err = srv.ListenAndServeTLS(config.Server.Cert, config.Server.Key)
	if err != nil {
		log.Fatal(err)
	}

}
