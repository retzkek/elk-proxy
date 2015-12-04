package main

import (
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

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

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if auth, _ := authorizedCN(req.TLS.PeerCertificates); auth {
		p.proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}
