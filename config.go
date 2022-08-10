package main

import (
	"crypto/rand"
	"crypto/x509"
	"path"
	"github.com/BurntSushi/toml"
	"os"
	"crypto/rsa"
	"fmt"
)

type authConfig struct {
	URL string
	Port uint16
}

type accountConfig struct {
	URL string
	Port uint16
}

type sessionConfig struct {
	URL string
	Port uint16
}

type servicesConfig struct {
	URL string
	Port uint16
}

type frontConfig struct {
	URL string
	Port uint16
}

type Config struct {
	DataDirectory string
	ApplicationOwner string
	FallbackSessionServers []string
	AllowHighResolutionSkins bool
	FrontEndServer frontConfig
	AuthServer authConfig
	AccountServer accountConfig
	SessionServer sessionConfig
	ServicesServer servicesConfig
}

func defaultConfig() Config {
	return Config{
		DataDirectory: "/var/lib/drasl",
		ApplicationOwner: "",
		AllowHighResolutionSkins: false,
		FallbackSessionServers: []string{},
		FrontEndServer: frontConfig{
			URL: "https://drasl.example.com",
			Port: 9090,
		},
		AuthServer: authConfig{
			URL: "https://auth.drasl.example.com",
			Port: 9091,
		},
		AccountServer: accountConfig{
			URL: "https://account.drasl.example.com",
			Port: 9092,
		},
		SessionServer: sessionConfig{
			URL: "https://session.drasl.example.com",
			Port: 9093,
		},
		ServicesServer: servicesConfig{
			URL: "https://services.drasl.example.com",
			Port: 9094,
		},
	}
}

func ReadOrCreateConfig(path string) *Config {
	config := defaultConfig()

	_, err := os.Stat(path)
	if err != nil {
		// File doesn't exist? Try to create it
		f, err := os.Create(path)
		Check(err)

		defer f.Close()

		err = toml.NewEncoder(f).Encode(config)
		Check(err)
	}

	_, err = toml.DecodeFile(path, &config)
	fmt.Println(config)
	Check(err)

	return &config
}

func ReadOrCreateKey(config *Config) *rsa.PrivateKey {
	err := os.MkdirAll(config.DataDirectory, os.ModePerm)
	path := path.Join(config.DataDirectory, "key.pkcs8")

	der, err := os.ReadFile(path)
	if err == nil {
		key, err := x509.ParsePKCS8PrivateKey(der)
		Check(err)

		return key.(*rsa.PrivateKey)
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		Check(err)

		der, err := x509.MarshalPKCS8PrivateKey(key)
		err = os.WriteFile(path, der, 0600)
		Check(err)

		return key
	}
}
