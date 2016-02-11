package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
)

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

func (p *ProxyServer) authorize(req *http.Request, authType string, authCNs []string) (bool, string) {
	switch authType {
	case "any":
		return true, "anonymous access"
	case "any_cert":
		if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
			return true, "user presented valid certificate"
		}
	case "cert":
		for _, presCert := range req.TLS.PeerCertificates {
			for _, cn := range authCNs {
				if presCert.Subject.CommonName == cn {
					return true, fmt.Sprintf("user presented certificate with authorized CommonName (%s)", cn)
				}
			}
		}
	}
	return false, ""
}

func (p *ProxyServer) authorizeRequest(req *http.Request, role string) bool {
	logger := log.WithFields(log.Fields{
		"path":    req.URL.Path,
		"method":  req.Method,
		"address": req.RemoteAddr,
	})
	if authed, authReason := p.authorize(req, p.Config.Global.AdminAuth, p.Config.Global.AdminCerts); authed {
		logger.Infof("authorized global admin: %s", authReason)
		return true
	}
	if role == "write" {
		if authed, authReason := p.authorize(req, p.Config.Global.WriteAuth, p.Config.Global.WriteCerts); authed {
			logger.Infof("authorized global write: %s", authReason)
			logger.Info(authReason)
			return true
		}
	}
	if role == "read" {
		if authed, authReason := p.authorize(req, p.Config.Global.ReadAuth, p.Config.Global.ReadCerts); authed {
			logger.Infof("authorized global read: %s", authReason)
			return true
		}
	}

	// index-specific auth
	for _, index := range p.Config.Indexes {
		matched, err := regexp.MatchString(index.IndexPattern, req.URL.Path)
		if err != nil {
			logger.Errorf("unauthorized due to error: %s", err)
			return false
		}
		if matched {
			if authed, authReason := p.authorize(req, index.AdminAuth, index.AdminCerts); authed {
				logger.WithField("index", index.IndexPattern).Infof("authorized index admin: %s", authReason)
				return true
			}
			if role == "write" {
				if authed, authReason := p.authorize(req, index.WriteAuth, index.WriteCerts); authed {
					logger.WithField("index", index.IndexPattern).Infof("authorized index write: %s", authReason)
					return true
				}
			}
			if role == "read" {
				if authed, authReason := p.authorize(req, index.ReadAuth, index.ReadCerts); authed {
					logger.WithField("index", index.IndexPattern).Infof("authorized index read: %s", authReason)
					return true
				}
			}
		}
	}
	logger.Warning("unauthorized")
	return false
}

func (p *ProxyServer) ServeRead(w http.ResponseWriter, req *http.Request) {
	if p.authorizeRequest(req, "read") {
		p.Proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

func (p *ProxyServer) ServeWrite(w http.ResponseWriter, req *http.Request) {
	if p.authorizeRequest(req, "write") {
		p.Proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

func (p *ProxyServer) ServeAdmin(w http.ResponseWriter, req *http.Request) {
	if p.authorizeRequest(req, "admin") {
		p.Proxy.ServeHTTP(w, req)
	} else {
		http.Error(w, "not authorized", http.StatusUnauthorized)
	}
}

func main() {
	log.WithField("file", "test.toml").Info("Reading config file")
	config, err := ReadConfig("test.toml")
	if err != nil {
		log.Fatal(err)
	}
	j, err := json.MarshalIndent(config, "..", "\t")
	if err != nil {
		log.Infof("Config: %v", config)
	} else {
		log.Infof("Config: %s", j)
	}

	r := mux.NewRouter()

	proxy := NewProxyServer(config)
	// Admin
	r.PathPrefix("/_").Methods("GET").HandlerFunc(proxy.ServeAdmin)
	r.PathPrefix("/_").Methods("POST").HandlerFunc(proxy.ServeAdmin)
	r.PathPrefix("/").Methods("DELETE").HandlerFunc(proxy.ServeAdmin)
	// Write
	r.PathPrefix("/").Methods("POST").HandlerFunc(proxy.ServeWrite)
	// Read
	r.PathPrefix("/").Methods("GET").HandlerFunc(proxy.ServeRead)

	pool := x509.NewCertPool()
	for _, ca := range config.Server.CaCerts {
		log.WithField("file", ca).Info("Loading CA certs")
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

	log.WithField("address", config.Server.Listen).Info("listening")
	srv := http.Server{Addr: config.Server.Listen}
	srv.TLSConfig = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs: pool}
	err = srv.ListenAndServeTLS(config.Server.Cert, config.Server.Key)
	if err != nil {
		log.Fatal(err)
	}

}
