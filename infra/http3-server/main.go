package main

import (
	"log"
	"net/http"
	"runtime/debug"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	bi, ok := debug.ReadBuildInfo()
	version := "unknown"
	if ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/quic-go/quic-go" {
				version = dep.Version
				break
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http3.Server{
		Addr:    ":443",
		Handler: mux,
	}

	log.Printf("quic-go %s HTTP/3 server listening on :443/udp (TLS)", version)
	if err := server.ListenAndServeTLS("/certs/server.crt", "/certs/server.key"); err != nil {
		log.Fatal(err)
	}
}
