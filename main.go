package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"net/http"
	"os"
)

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
	http.Handle("/", r)

	proxy := NewProxyServer(config)
	// Admin
	r.PathPrefix("/_").Methods("GET").HandlerFunc(proxy.ServeAdmin)
	r.PathPrefix("/_").Methods("POST").HandlerFunc(proxy.ServeAdmin)
	r.PathPrefix("/").Methods("DELETE").HandlerFunc(proxy.ServeAdmin)
	// Write
	r.PathPrefix("/").Methods("POST").HandlerFunc(proxy.ServeWrite)
	// Read
	r.PathPrefix("/").Methods("GET").HandlerFunc(proxy.ServeRead)

	log.WithField("address", config.Server.Listen).Info("listening")
	srv := http.Server{Addr: config.Server.Listen}
	pool, err := loadCerts(config.Server.CaCerts)
	if err != nil {
		log.Fatal(err)
	}
	srv.TLSConfig = &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}
	err = srv.ListenAndServeTLS(config.Server.Cert, config.Server.Key)
	if err != nil {
		log.Fatal(err)
	}

}
