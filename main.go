package main

import (
	"crypto/tls"
	"github.com/gorilla/mux"
	"github.com/vvinokurshin/ProxyServerCourseVK/api"
	myhttp "github.com/vvinokurshin/ProxyServerCourseVK/http"
	"github.com/vvinokurshin/ProxyServerCourseVK/pkg"
	"log"
	"net/http"
	"time"
)

func main() {
	router := mux.NewRouter()
	api.AddRoutes(router)
	apiServer := http.Server{
		Addr:         ":8000",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := apiServer.ListenAndServe(); err != nil {
			log.Fatalf("server stopped %v", err)
		}
	}()

	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			if r.Method == http.MethodConnect {
				err = myhttp.ProxyHttps(w, r)
			} else {
				err = myhttp.ProxyHttp(w, r)
			}

			if err != nil {
				pkg.SendJSON(w, http.StatusInternalServerError, err)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	server.ListenAndServe()
}
