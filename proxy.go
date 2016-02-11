package main

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"net/url"
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
