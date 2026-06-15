package api

import (
	"encoding/json"
	"log"
	"net/http"
	"snowden/config"

	"github.com/gorilla/mux"
)

func (s *Server) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/api/v1/health", config.LogHandler(makeHTTPHandleFunc(HealthHandler))).Methods("GET")
	router.HandleFunc("/api/v1/vulnerability/cve", config.LogHandler(makeHTTPHandleFunc(ReadVulnerabilityByCve))).Methods("GET")
	router.HandleFunc("/api/v1/vulnerability/cwe", config.LogHandler(makeHTTPHandleFunc(ReadVulnerabilityByCwe))).Methods("GET")

	if err := http.ListenAndServe(s.Port, router); err != nil {
		log.Fatal("server failed: ", err)
	}
}

func NewApiServer(port string) *Server {
	return &Server{
		Port: port,
	}
}

func WriteJson(w http.ResponseWriter, status int, value any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(value)
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			err := WriteJson(w, http.StatusBadRequest, Error{Error: err.Error()})
			if err != nil {
				return
			}
		}
	}
}

type Server struct {
	Port string
}

type apiFunc func(w http.ResponseWriter, r *http.Request) error

type Error struct {
	Error string `json:"error"`
}
