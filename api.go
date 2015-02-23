package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type keyRequest struct {
	Roles  []string `json:"roles"`
	APIKey string   `json:"api_key"`
}

type keyResponse struct {
	Key string `json:"key"`

	keyRequest
}

type errResponse struct {
	Error errDetail `json:"proxy_error"`
}

type errDetail struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// API provides configuration for the internal API for jsonproxy.
type API struct {
	KeyGen     func(*Key) ([]byte, error)
	KeyEncoder func([]byte) string
	Roles      map[string]Role
}

// Handler returns an http.Handler containing the internal API routes for
// jsonproxy.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/keys", a.generateKey)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		respond(w, errResponse{Error: errDetail{Code: "not_found"}},
			http.StatusNotFound)
		return
	})

	return mux
}

func (a *API) generateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		respond(w, errResponse{Error: errDetail{Code: "not_found"}},
			http.StatusNotFound)
		return
	}

	var req keyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ed := errDetail{
			Code:    "invalid_request",
			Message: "Unable to parse body as JSON.",
		}
		respond(w, errResponse{Error: ed}, http.StatusNotFound)
		return
	}

	for _, role := range req.Roles {
		if _, ok := a.Roles[role]; !ok {
			respond(w, errResponse{Error: errDetail{
				Code:    "not_found",
				Message: fmt.Sprintf("Role %s does not exist", role),
			}}, http.StatusNotFound)
			return
		}
	}

	key := Key{Roles: req.Roles, APIKey: req.APIKey}

	ciphertext, err := a.KeyGen(&key)
	if err != nil {
		panic(err)
	}

	resp := keyResponse{a.KeyEncoder(ciphertext), req}
	respond(w, resp, http.StatusOK)
}

func respond(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
	}
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
