// Copyright 2026 J3nna Technologies, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package agentkit

// Enroll is the agent-side of the console's enrollment flow. An agent calls it to register with the
// authority and obtain (a) its console-signed grant and (b) the authority root public key — everything
// needed to join the mesh under authorized discovery. The operator approves the request in the console
// (matching the out-of-band code), then this returns and the agent Opens with the same identity file.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/J3nnaAI/mesh/jip"
)

// Enroll registers with the console at consoleURL and BLOCKS until an operator approves (or ctx ends),
// returning the issued grant + the authority root pubkey. Pass them as Options.Grant +
// Options.AuthorityRoot (with the SAME identityFile) to Open under authorized discovery. onOOB receives
// the out-of-band code to display so the operator can confirm it; nil = no callback.
func Enroll(ctx context.Context, consoleURL, clientName, identityFile string, tier int, onOOB func(string)) (*jip.Grant, []byte, error) {
	id, pub, err := jip.EnsureIdentity(identityFile)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: %w", err)
	}
	base := strings.TrimRight(consoleURL, "/")
	hc := &http.Client{Timeout: 15 * time.Second, Transport: InsecureLoopbackTransport()}

	// The console may not be reachable yet — under an orchestrator (Docker Compose / Kubernetes) the
	// console and this agent can start concurrently with no ordering guarantee. Retry the initial contact
	// with backoff until it succeeds or ctx ends, instead of failing fast (which would crash-loop the pod).
	root, err := retry(ctx, "fetch authority root", func() ([]byte, error) { return fetchRoot(ctx, hc, base) })
	if err != nil {
		return nil, nil, err
	}

	reqBody, _ := json.Marshal(map[string]any{
		"kind": "agent", "client_name": clientName, "subject": string(id),
		"public_key": base64.StdEncoding.EncodeToString(pub), "tier": tier,
	})
	var sub struct {
		RequestID string `json:"request_id"`
		Oob       string `json:"oob"`
	}
	if _, err := retry(ctx, "submit enrollment", func() ([]byte, error) {
		return nil, doJSON(ctx, hc, http.MethodPost, base+"/enroll", reqBody, &sub)
	}); err != nil {
		return nil, nil, err
	}
	if sub.RequestID == "" {
		return nil, nil, fmt.Errorf("enrollment: no request id returned")
	}
	if onOOB != nil {
		onOOB(sub.Oob)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		var st struct {
			Status string     `json:"status"`
			Grant  *jip.Grant `json:"grant"`
		}
		if err := doJSON(ctx, hc, http.MethodGet, base+"/enroll/"+sub.RequestID, nil, &st); err == nil {
			switch st.Status {
			case "approved":
				if st.Grant == nil {
					return nil, nil, fmt.Errorf("approved but no grant returned")
				}
				return st.Grant, root, nil
			case "denied":
				return nil, nil, fmt.Errorf("enrollment denied by operator")
			}
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-tick.C:
		}
	}
}

// retry runs fn with a fixed backoff until it succeeds or ctx ends — used for the initial console
// contact so an agent started before the console is reachable waits for it instead of crashing.
func retry(ctx context.Context, what string, fn func() ([]byte, error)) ([]byte, error) {
	const backoff = 2 * time.Second
	for {
		out, err := fn()
		if err == nil {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w (last error: %v)", what, ctx.Err(), err)
		case <-time.After(backoff):
		}
	}
}

func fetchRoot(ctx context.Context, hc *http.Client, base string) ([]byte, error) {
	var a struct {
		RootPublicKey string `json:"root_public_key"`
	}
	if err := doJSON(ctx, hc, http.MethodGet, base+"/authority", nil, &a); err != nil {
		return nil, err
	}
	root, err := base64.StdEncoding.DecodeString(a.RootPublicKey)
	if err != nil || len(root) == 0 {
		return nil, fmt.Errorf("bad authority root key")
	}
	return root, nil
}

func doJSON(ctx context.Context, hc *http.Client, method, url string, body []byte, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s: %d: %s", method, url, resp.StatusCode, string(raw))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
