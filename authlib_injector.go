package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/url"
)

type authlibInjectorMeta struct {
	ImplementationName    string               `json:"implementationName"`
	ImplementationVersion string               `json:"implementationVersion"`
	Links                 authlibInjectorLinks `json:"links"`
	ServerName            string               `json:"serverName"`
}

type authlibInjectorLinks struct {
	Homepage string `json:"homepage"`
	Register string `json:"register"`
}

type authlibInjectorResponse struct {
	Meta                authlibInjectorMeta `json:"meta"`
	SignaturePublickey  string              `json:"signaturePublickey"`
	SignaturePublickeys []string            `json:"signaturePublickeys"`
	SkinDomains         []string            `json:"skinDomains"`
}

func authlibInjectorSerializeKey(key *rsa.PublicKey) (string, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return string(pubPEM[:]), nil
}

func AuthlibInjectorRoot(app *App) func(c echo.Context) error {
	skinDomains := make([]string, 0, 1+len(app.Config.FallbackAPIServers))
	skinDomains = append(skinDomains, app.Config.Domain)
	for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
		for _, skinDomain := range fallbackAPIServer.SkinDomains {
			if !Contains(skinDomains, skinDomain) {
				skinDomains = append(skinDomains, skinDomain)
			}
		}
	}

	signaturePublicKey, err := authlibInjectorSerializeKey(&app.Key.PublicKey)
	Check(err)

	signaturePublicKeys := make([]string, 0, len(app.ProfilePropertyKeys))
	for _, key := range app.ProfilePropertyKeys {
		serialized, err := authlibInjectorSerializeKey(&key)
		Check(err)
		signaturePublicKeys = append(signaturePublicKeys, serialized)
	}

	responseBlob := Unwrap(json.Marshal(authlibInjectorResponse{
		Meta: authlibInjectorMeta{
			ImplementationName:    "Drasl",
			ImplementationVersion: Constants.Version,
			Links: authlibInjectorLinks{
				Homepage: app.FrontEndURL,
				Register: Unwrap(url.JoinPath(app.FrontEndURL, "drasl/registration")),
			},
			ServerName: app.Config.InstanceName,
		},
		SignaturePublickey:  signaturePublicKey,
		SignaturePublickeys: signaturePublicKeys,
		SkinDomains:         skinDomains,
	}))

	return func(c echo.Context) error {
		return c.JSONBlob(http.StatusOK, responseBlob)
	}
}
