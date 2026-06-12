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

// Connector tool-approval (M8) — the operator policy for WHICH of the desktop's tools a connector exposes to
// the mesh. Default is DENY-ALL ("secured by default — nothing exposed"); an operator grants exposure at three
// granularities, widest-wins: approve ALL, approve CATEGORY(ies), or approve INDIVIDUAL tools. This is the
// backend the infosec tool-approval UI drives (see desktop-design/app-infosec.html). It governs EXPOSURE only;
// the desktop still gates each actual call on its grant+tier, and a T2 (write) tool's call still raises the
// local consent modal — exposure is necessary, not sufficient.

import "encoding/json"

// ToolTier mirrors the desktop's tiering: T1 is read-only (low risk), T2 is write/control (raises consent).
type ToolTier int

const (
	TierReadOnly ToolTier = 1 // T1 — screenshot, clipboard-read, list panes, …
	TierWrite    ToolTier = 2 // T2 — send keys, click, navigate, write clipboard, …
)

// ToolDef is one entry in the desktop's tool catalog.
type ToolDef struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Tier     ToolTier `json:"tier"`
}

// ApprovalPolicy is the operator's exposure decision. The zero value is DENY-ALL (the safe default): a fresh
// policy exposes nothing. Marshals to JSON so a connector persists the operator's choices.
type ApprovalPolicy struct {
	All        bool            `json:"all,omitempty"`        // approve everything
	Categories map[string]bool `json:"categories,omitempty"` // approved categories
	Tools      map[string]bool `json:"tools,omitempty"`      // approved individual tools
}

// NewApprovalPolicy returns a deny-all policy (nothing exposed).
func NewApprovalPolicy() *ApprovalPolicy { return &ApprovalPolicy{} }

// MayExpose reports whether the tool is exposed to the mesh under this policy. DENY-ALL by default; widest
// grant wins (all > category > individual).
func (p *ApprovalPolicy) MayExpose(t ToolDef) bool {
	if p == nil {
		return false
	}
	if p.All {
		return true
	}
	if p.Categories[t.Category] {
		return true
	}
	return p.Tools[t.Name]
}

func (p *ApprovalPolicy) ApproveAll() { p.All = true }
func (p *ApprovalPolicy) DenyAll()    { *p = ApprovalPolicy{} } // reset to the secure default

func (p *ApprovalPolicy) ApproveCategory(cat string) {
	if p.Categories == nil {
		p.Categories = map[string]bool{}
	}
	p.Categories[cat] = true
}
func (p *ApprovalPolicy) RevokeCategory(cat string) { delete(p.Categories, cat) }

func (p *ApprovalPolicy) ApproveTool(name string) {
	if p.Tools == nil {
		p.Tools = map[string]bool{}
	}
	p.Tools[name] = true
}
func (p *ApprovalPolicy) RevokeTool(name string) { delete(p.Tools, name) }

// Expose returns the subset of the catalog the policy exposes to the mesh — what a connector advertises.
func (p *ApprovalPolicy) Expose(catalog []ToolDef) []ToolDef {
	out := []ToolDef{}
	for _, t := range catalog {
		if p.MayExpose(t) {
			out = append(out, t)
		}
	}
	return out
}

// Status summarizes a policy against a catalog — the numbers the infosec UI shows.
type ApprovalStatus struct {
	Exposed       int            `json:"exposed"`        // tools exposed
	Total         int            `json:"total"`          // tools in the catalog
	ExposesWrite  bool           `json:"exposes_write"`  // any exposed T2 tool → the consent-modal reminder applies
	ByCategory    map[string]int `json:"by_category"`    // exposed count per category
	CategoryTotal map[string]int `json:"category_total"` // total per category (for "1 of N" readouts)
}

func (p *ApprovalPolicy) Status(catalog []ToolDef) ApprovalStatus {
	s := ApprovalStatus{Total: len(catalog), ByCategory: map[string]int{}, CategoryTotal: map[string]int{}}
	for _, t := range catalog {
		s.CategoryTotal[t.Category]++
		if p.MayExpose(t) {
			s.Exposed++
			s.ByCategory[t.Category]++
			if t.Tier == TierWrite {
				s.ExposesWrite = true
			}
		}
	}
	return s
}

// MarshalPolicy / UnmarshalPolicy persist an operator's choices.
func MarshalPolicy(p *ApprovalPolicy) ([]byte, error) { return json.Marshal(p) }
func UnmarshalPolicy(b []byte) (*ApprovalPolicy, error) {
	var p ApprovalPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
