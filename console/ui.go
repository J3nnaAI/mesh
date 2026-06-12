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

package main

// The console's management UI — a pure HTML/CSS/JS single-page app embedded into the binary and served
// at the root. The API routes are registered on specific paths and take precedence; this mounts the
// static assets as the catch-all. Loopback is trusted, so a locally-served UI needs no token; a bearer
// token (Settings) enables remote use. No build step, no external assets — the files are embedded as-is.

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed web
var webFS embed.FS

// mountUI serves the embedded web/ directory at "/". Call after the API routes are registered so the
// specific API patterns win and only unmatched paths (/, /app.js, /style.css, …) fall through to here.
func mountUI(mux *http.ServeMux) error {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return nil
}
