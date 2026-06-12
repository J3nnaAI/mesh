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

import "testing"

// a small representative desktop catalog: 3 categories, T1/T2 mix.
var catalog = []ToolDef{
	{"screenshot_pane", "capture", TierReadOnly},
	{"clipboard_read", "capture", TierReadOnly},
	{"list_panes", "panes", TierReadOnly},
	{"open_pane", "panes", TierWrite},
	{"send_keys_to_pane", "input", TierWrite},
	{"click_pane", "input", TierWrite},
}

func exposedNames(p *ApprovalPolicy) map[string]bool {
	m := map[string]bool{}
	for _, t := range p.Expose(catalog) {
		m[t.Name] = true
	}
	return m
}

// TestApprovalDenyByDefault: a fresh policy exposes NOTHING (secured by default), and the status reflects it.
func TestApprovalDenyByDefault(t *testing.T) {
	p := NewApprovalPolicy()
	if len(p.Expose(catalog)) != 0 {
		t.Errorf("deny-all default must expose nothing, got %d", len(p.Expose(catalog)))
	}
	s := p.Status(catalog)
	if s.Exposed != 0 || s.Total != 6 || s.ExposesWrite {
		t.Errorf("default status wrong: %+v", s)
	}
}

// TestApprovalGranularities: approve individual, category, and all — widest wins; revoke works.
func TestApprovalGranularities(t *testing.T) {
	p := NewApprovalPolicy()

	// individual
	p.ApproveTool("screenshot_pane")
	got := exposedNames(p)
	if !got["screenshot_pane"] || len(got) != 1 {
		t.Errorf("individual approve: %v", got)
	}

	// category (exposes both capture tools; screenshot already individually approved)
	p.ApproveCategory("capture")
	got = exposedNames(p)
	if !got["screenshot_pane"] || !got["clipboard_read"] || len(got) != 2 {
		t.Errorf("category approve: %v", got)
	}
	// the capture category is all-T1 → no write exposed yet
	if p.Status(catalog).ExposesWrite {
		t.Errorf("capture is read-only; ExposesWrite should be false")
	}

	// approving a T2 category flips ExposesWrite (the consent-modal reminder).
	p.ApproveCategory("input")
	if !p.Status(catalog).ExposesWrite {
		t.Errorf("input is T2; ExposesWrite should be true")
	}

	// revoke a category.
	p.RevokeCategory("input")
	if got := exposedNames(p); got["send_keys_to_pane"] {
		t.Errorf("revoked input category still exposed: %v", got)
	}

	// approve-all exposes everything; deny-all resets to secure default.
	p.ApproveAll()
	if len(p.Expose(catalog)) != len(catalog) {
		t.Errorf("approve-all should expose all")
	}
	p.DenyAll()
	if len(p.Expose(catalog)) != 0 {
		t.Errorf("deny-all should reset to nothing exposed")
	}
}

// TestApprovalStatusCounts: the per-category counts the infosec UI shows ("1 of N").
func TestApprovalStatusCounts(t *testing.T) {
	p := NewApprovalPolicy()
	p.ApproveTool("open_pane") // one T2 tool in the "panes" category (which has 2 total)
	s := p.Status(catalog)
	if s.Exposed != 1 || s.ByCategory["panes"] != 1 || s.CategoryTotal["panes"] != 2 || !s.ExposesWrite {
		t.Errorf("status counts wrong: %+v", s)
	}
}

// TestApprovalPersist: an operator's choices round-trip through JSON.
func TestApprovalPersist(t *testing.T) {
	p := NewApprovalPolicy()
	p.ApproveCategory("capture")
	p.ApproveTool("open_pane")
	b, err := MarshalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := UnmarshalPolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.MayExpose(catalog[0]) || !p2.MayExpose(ToolDef{Name: "open_pane", Category: "panes", Tier: TierWrite}) {
		t.Errorf("policy did not round-trip: %s", b)
	}
	if p2.MayExpose(catalog[4]) { // send_keys was never approved
		t.Errorf("round-trip exposed an unapproved tool")
	}
}
