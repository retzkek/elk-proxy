package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"net/http"
	"os"
)

var (
	configFile string
	logLevel   string
)

func init() {
	flag.StringVar(&configFile, "c", "elk-proxy.toml", "config file")
	flag.StringVar(&logLevel, "l", "info", "log level (panic, fatal, error, warn, info, debug)")
}

func loadCerts(certs []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, ca := range certs {
		log.WithField("file", ca).Info("Loading CA certs")
		f, err := os.Open(ca)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(f); err != nil {
			return nil, err
		}
		if ok := pool.AppendCertsFromPEM(buf.Bytes()); !ok {
			return nil, err
		}
	}
	return pool, nil
}

func main() {
	flag.Parse()

	log.WithField("level", logLevel).Info("setting log level")
	lvl, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(lvl)

	log.WithField("file", configFile).Info("Reading config file")
	config, err := ReadConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}
	j, err := json.MarshalIndent(config, "..", "\t")
	if err != nil {
		log.Debugf("Config: %v", config)
	} else {
		log.Debugf("Config: %s", j)
	}

	r := mux.NewRouter()
	http.Handle("/", r)

	proxy := NewProxyServer(config)
	// Whitelist search endpoints for read access, everything else that starts with _ is restricted to admin
	r.PathPrefix("/_search").Methods("GET", "POST").HandlerFunc(proxy.ServeRead)
	r.PathPrefix("/_msearch").Methods("GET", "POST").HandlerFunc(proxy.ServeRead)
	r.Path("/{index:.*}/_search").Methods("GET", "POST").HandlerFunc(proxy.ServeRead)
	r.Path("/{index:.*}/_msearch").Methods("GET", "POST").HandlerFunc(proxy.ServeRead)
	// Admin
	r.PathPrefix("/_").HandlerFunc(proxy.ServeAdmin)
	r.PathPrefix("/").Methods("DELETE").HandlerFunc(proxy.ServeAdmin)
	// Write
	r.PathPrefix("/").Methods("POST", "PUT").HandlerFunc(proxy.ServeWrite)
	// Read
	r.PathPrefix("/").Methods("GET").HandlerFunc(proxy.ServeRead)

	srv := http.Server{Addr: config.Server.Listen}
	pool, err := loadCerts(config.Server.CaCerts)
	if err != nil {
		log.Fatal(err)
	}
	srv.TLSConfig = &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}
	log.WithField("address", config.Server.Listen).Info("listening")
	err = srv.ListenAndServeTLS(config.Server.Cert, config.Server.Key)
	if err != nil {
		log.Fatal(err)
	}

}
