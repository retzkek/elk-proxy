package main

import (
	"crypto/x509"
	"encoding/json"
)

type role struct {
	Auth  string
	Certs []x509.Certificate
}

type auth struct {
	IndexPattern string `json:"index_pattern"`
	Admin        role
	Write        role
	Read         role
}

type config struct {
	Listen      string
	Proxy       string
	CaCerts     []string `json:"ca_certs"`
	Cert        string
	Key         string
	AuthGlobal  auth   `json:"auth_global"`
	AuthIndexes []auth `json:"auth_indexes"`
}
