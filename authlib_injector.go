package main

import (
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
	Meta               authlibInjectorMeta `json:"meta"`
	SignaturePublickey string              `json:"signaturePublickey"`
	SkinDomains        []string            `json:"skinDomains"`
}

func AuthlibInjectorRoot(app *App) func(c echo.Context) error {
	skinDomains := make([]string, 0, 1+len(app.Config.FallbackAPIServers))
	skinDomains = append(skinDomains, app.Config.Domain)
	for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
		skinDomains = append(skinDomains, fallbackAPIServer.SkinDomains...)
	}

	pubDER := Unwrap(x509.MarshalPKIXPublicKey(&app.Key.PublicKey))
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	pubPEMString := string(pubPEM[:])

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
		SignaturePublickey: pubPEMString,
		SkinDomains:        skinDomains,
	}))
	return func(c echo.Context) error {
		return c.JSONBlob(http.StatusOK, responseBlob)
	}
}
