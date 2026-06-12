// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// operator is a DEV convenience for the showcase's container/cluster path: it stands in for the human who
// would otherwise approve each enrollment in the console UI. It polls the console for pending enrollments and
// approves them with the seeded operator bearer token, so `docker compose up` / a kubectl apply comes up
// hands-free. In a real deployment a person approves who joins — that is the whole point of the console; this
// is only for the self-contained demo. Pure standard library.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	console := envOr("OP_CONSOLE", "http://console:8455")
	token := envOr("OP_TOKEN", "")
	if token == "" {
		log.Fatalf("operator: OP_TOKEN (the seeded operator bearer token) is required")
	}
	log.Printf("operator: auto-approving enrollments at %s (DEV ONLY — a human approves in production)", console)
	for {
		for _, p := range pending(console, token) {
			approve(console, token, p.ID, p.OOB)
		}
		time.Sleep(1 * time.Second)
	}
}

type req struct {
	ID  string `json:"id"`
	OOB string `json:"oob"`
}

func pending(console, token string) []req {
	r, err := do(http.MethodGet, console+"/enroll/pending", token, nil)
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	var out struct {
		Pending []req `json:"pending"`
	}
	_ = json.NewDecoder(r.Body).Decode(&out)
	return out.Pending
}

func approve(console, token, id, oob string) {
	body, _ := json.Marshal(map[string]string{"oob": oob})
	r, err := do(http.MethodPost, console+"/enroll/"+id+"/approve", token, body)
	if err != nil {
		return
	}
	defer r.Body.Close()
	if r.StatusCode/100 == 2 {
		log.Printf("operator: approved enrollment %s", id)
	}
}

func do(method, url, token string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
