package main

import (
	"github.com/BurntSushi/toml"
)

type authConfig struct {
	IndexPattern string   `toml:"index_pattern"`
	AdminAuth    string   `toml:"admin_auth"`
	AdminCerts   []string `toml:"admin_certs"`
	WriteAuth    string   `toml:"write_auth"`
	WriteCerts   []string `toml:"write_certs"`
	ReadAuth     string   `toml:"read_auth"`
	ReadCerts    []string `toml:"read_certs"`
}

type serverConfig struct {
	Listen  string
	Proxy   string
	CaCerts []string `toml:"ca_certs"`
	Cert    string
	Key     string
}

type config struct {
	Server  serverConfig
	Global  authConfig
	Indexes []authConfig
}

func ReadConfig(filename string) (*config, error) {
	var conf config
	if _, err := toml.DecodeFile(filename, &conf); err != nil {
		return nil, err
	}
	return &conf, nil
}
