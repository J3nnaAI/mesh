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

package kernel

// The process executor — the kernel primitive the process pillar (CHARTER §5b)
// and the runtime control plane (§5e) build on. A plan is a `plan` node that
// `decomposes` into `step` nodes ordered by `depends_on`. The executor walks
// that DAG by DISCRETE, externally-gated transitions, and — critically — every
// step's lifecycle status lives ON the step node (Attrs["status"]), so the
// execution FRONTIER is in the graph, not a hidden call stack. That single
// decision is what makes a process durable, resumable across restarts, and
// inspectable/editable while it runs.
//
// Mechanism vs policy (§5g): the executor is pure mechanism — sequencing,
// frontier, gating, persistence. WHAT a step does is policy, supplied by the
// application as a StepRunner (a sub-deliberation, a retrieval, a tool/MCP call).
// Build capability as runners/thought-processes on this kernel, never into it.

import (
	"context"
	"errors"
	"sort"
)

// StepStatus is a step's lifecycle, persisted on the step node's Attrs so the
// frontier is recoverable from the graph alone.
type StepStatus string

const (
	StepPending StepStatus = "pending" // untouched, or deps not yet satisfied
	StepRunning StepStatus = "running" // currently executing
	StepDone    StepStatus = "done"    // completed; effect recorded
	StepFailed  StepStatus = "failed"  // the runner reported failure
	StepBlocked StepStatus = "blocked" // a dependency failed → unreachable
)

const (
	stepStatusAttr = "status"
	stepEffectAttr = "effect"
)

// ErrPaused is returned by Run when the control plane pauses the loop (a
// breakpoint, a single-step request, or an attach). Re-call Run to resume — the
// frontier is recomputed from the graph, so any edits made while paused apply.
var ErrPaused = errors.New("kernel: process paused by control plane")

// StepOutcome is what a StepRunner reports for one step. Status should be
// StepDone or StepFailed (the executor manages pending/running/blocked).
type StepOutcome struct {
	Status StepStatus
	Effect string // recorded onto the step and, if non-empty, as an evidence node
}

// StepInput is one upstream dependency's result, handed to a step that depends on
// it — the kernel's step-to-step DATA FLOW. A runner physically cannot read the
// effects of steps the executor never passes it, so this is kernel mechanism, not
// something a policy-layer runner could supply for itself.
type StepInput struct {
	ID     string
	Label  string
	Effect string
}

// StepRunner is the POLICY seam: it performs one step's action given the step and
// the results of its dependencies. Supplied by the application; the executor never
// assumes what a step means.
type StepRunner interface {
	RunStep(ctx context.Context, step Node, inputs []StepInput) StepOutcome
}

// RunnerFunc adapts a plain function to a StepRunner.
type RunnerFunc func(ctx context.Context, step Node, inputs []StepInput) StepOutcome

// RunStep implements StepRunner.
func (f RunnerFunc) RunStep(ctx context.Context, step Node, inputs []StepInput) StepOutcome {
	return f(ctx, step, inputs)
}

// ControlDecision is the control plane's verdict before a step runs under Run.
type ControlDecision int

const (
	Proceed ControlDecision = iota // run the step
	Pause                          // stop the Run loop here (breakpoint / attach)
)

// Controller is the OPERABILITY seam (§5e): consulted before every transition
// under Run, it lets a human or AI set breakpoints, pause/resume, and attach to
// a LIVE process without stopping the engine. nil = always Proceed.
type Controller interface {
	BeforeStep(ctx context.Context, step Node, ex *Executor) ControlDecision
}

// ControlFunc adapts a plain function to a Controller.
type ControlFunc func(ctx context.Context, step Node, ex *Executor) ControlDecision

// BeforeStep implements Controller.
func (f ControlFunc) BeforeStep(ctx context.Context, step Node, ex *Executor) ControlDecision {
	return f(ctx, step, ex)
}

// Executor walks a plan's step-DAG by discrete, externally-gated transitions.
type Executor struct {
	eng     *Engine
	planID  string
	runner  StepRunner
	control Controller // optional control plane
}

// NewExecutor builds an executor over the steps of plan planID using runner for
// step actions. Steps are the `step` nodes the plan `decomposes` into; their
// order is constrained by `depends_on` (step → prerequisite).
func (e *Engine) NewExecutor(planID string, runner StepRunner) *Executor {
	return &Executor{eng: e, planID: planID, runner: runner}
}

// WithController attaches a control plane (breakpoints / pause / attach) used by
// Run. Step() always advances unconditionally regardless of the controller.
func (x *Executor) WithController(c Controller) *Executor { x.control = c; return x }

// steps returns the plan's live step nodes, in a deterministic order.
func (x *Executor) steps() []Node {
	var out []Node
	seen := map[string]bool{}
	for _, ed := range x.eng.Store().EdgesFrom(x.planID) {
		if ed.Kind != EdgeDecomposes || ed.Tombstone != nil {
			continue
		}
		n, ok := x.eng.Store().GetNode(ed.To)
		if ok && n.Tombstone == nil && n.Kind == KindStep && !seen[n.ID] {
			seen[n.ID] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func stepStatus(n Node) StepStatus {
	if n.Attrs != nil {
		if s := n.Attrs[stepStatusAttr]; s != "" {
			return StepStatus(s)
		}
	}
	return StepPending
}

func (x *Executor) setStatus(n Node, s StepStatus, effect string) {
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	n.Attrs[stepStatusAttr] = string(s)
	if effect != "" {
		n.Attrs[stepEffectAttr] = effect
	}
	_ = x.eng.Store().PutNode(n)
}

// depsState reports whether a step's dependencies are all done (ready), or
// whether any dependency failed/blocked (blocked → the step is unreachable).
func (x *Executor) depsState(n Node) (ready, blocked bool) {
	ready = true
	for _, ed := range x.eng.Store().EdgesFrom(n.ID) {
		if ed.Kind != EdgeDependsOn || ed.Tombstone != nil {
			continue
		}
		dep, ok := x.eng.Store().GetNode(ed.To)
		if !ok || dep.Tombstone != nil {
			continue
		}
		switch stepStatus(dep) {
		case StepDone:
			// satisfied
		case StepFailed, StepBlocked:
			return false, true
		default:
			ready = false
		}
	}
	return ready, blocked
}

// Frontier returns the steps currently ready to run (deps satisfied, not yet
// running/terminal). It first propagates blocked-status to a fixed point (a
// failed dependency blocks its dependents transitively), so the result is
// correct regardless of iteration order. Inspect it any time — it IS the live
// "what runs next".
func (x *Executor) Frontier() []Node {
	for { // propagate blocked transitively until stable
		changed := false
		for _, n := range x.steps() {
			switch stepStatus(n) {
			case StepRunning, StepDone, StepFailed, StepBlocked:
				continue
			}
			if _, blocked := x.depsState(n); blocked {
				x.setStatus(n, StepBlocked, "dependency failed")
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	var f []Node
	for _, n := range x.steps() {
		switch stepStatus(n) {
		case StepRunning, StepDone, StepFailed, StepBlocked:
			continue
		}
		if ready, _ := x.depsState(n); ready {
			f = append(f, n)
		}
	}
	return f
}

// StepResult reports one completed transition.
type StepResult struct {
	Step   Node
	Status StepStatus
	Effect string
}

// Step advances EXACTLY ONE transition unconditionally: it picks the next ready
// step, runs it, and persists the outcome. This is the manual single-step the
// operator drives (it ignores the controller — use it to step past a
// breakpoint). Returns advanced=false when nothing is ready (done or stalled).
func (x *Executor) Step(ctx context.Context) (StepResult, bool) {
	f := x.Frontier()
	if len(f) == 0 {
		return StepResult{}, false
	}
	return x.runOne(ctx, f[0]), true
}

// Run auto-advances transitions until the frontier empties or the control plane
// pauses (ErrPaused). Re-call to resume: the frontier is recomputed from the
// graph each iteration, so live edits made while paused take effect.
func (x *Executor) Run(ctx context.Context) ([]StepResult, error) {
	var done []StepResult
	for {
		select {
		case <-ctx.Done():
			return done, ctx.Err()
		default:
		}
		f := x.Frontier()
		if len(f) == 0 {
			return done, nil
		}
		next := f[0]
		if x.control != nil && x.control.BeforeStep(ctx, next, x) == Pause {
			return done, ErrPaused
		}
		done = append(done, x.runOne(ctx, next))
	}
}

// inputsFor returns the results of a step's depends_on predecessors — its
// upstream data. The executor hands these to the runner so a step can build on
// what its dependencies produced (e.g. a write step uses a synthesis step's text).
func (x *Executor) inputsFor(step Node) []StepInput {
	var in []StepInput
	for _, ed := range x.eng.Store().EdgesFrom(step.ID) {
		if ed.Kind != EdgeDependsOn || ed.Tombstone != nil {
			continue
		}
		dep, ok := x.eng.Store().GetNode(ed.To)
		if !ok || dep.Tombstone != nil {
			continue
		}
		eff := ""
		if dep.Attrs != nil {
			eff = dep.Attrs[stepEffectAttr]
		}
		in = append(in, StepInput{ID: dep.ID, Label: dep.Label, Effect: eff})
	}
	return in
}

func (x *Executor) runOne(ctx context.Context, next Node) StepResult {
	x.setStatus(next, StepRunning, "")
	if cur, ok := x.eng.Store().GetNode(next.ID); ok {
		next = cur // re-read: a controller may have edited the step while paused
	}
	out := x.runner.RunStep(ctx, next, x.inputsFor(next))
	st := out.Status
	if st != StepDone && st != StepFailed {
		st = StepDone // runner reports only terminal states; default to done
	}
	x.setStatus(next, st, out.Effect)
	if out.Effect != "" { // record the effect as an auditable evidence node
		if ev, err := x.eng.AddNode(Node{Kind: KindEvidence, Namespace: next.Namespace, Label: "effect",
			Body: out.Effect, Base: 0.3, Prov: Provenance{Source: "executor"}}); err == nil && ev.ID != "" {
			_, _ = x.eng.AddEdge(Edge{Kind: EdgeJustifies, Namespace: next.Namespace, From: ev.ID, To: next.ID, Weight: 0.5})
		}
	}
	return StepResult{Step: next, Status: st, Effect: out.Effect}
}

// StepView is a read-only snapshot of one step for an attached operator/UI.
type StepView struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Status    StepStatus `json:"status"`
	Effect    string     `json:"effect,omitempty"`
	DependsOn []string   `json:"depends_on,omitempty"`
}

// Steps returns a read-only view of every step and its live state — the detail
// behind Status(), for observing/debugging a running process (§5e).
func (x *Executor) Steps() []StepView {
	var v []StepView
	for _, n := range x.steps() {
		sv := StepView{ID: n.ID, Label: n.Label, Status: stepStatus(n)}
		if n.Attrs != nil {
			sv.Effect = n.Attrs[stepEffectAttr]
		}
		for _, ed := range x.eng.Store().EdgesFrom(n.ID) {
			if ed.Kind == EdgeDependsOn && ed.Tombstone == nil {
				sv.DependsOn = append(sv.DependsOn, ed.To)
			}
		}
		v = append(v, sv)
	}
	return v
}

// PlanID returns the id of the plan this executor runs.
func (x *Executor) PlanID() string { return x.planID }

// Status reports how many steps are in each lifecycle state — the live process
// dashboard for an attached operator.
func (x *Executor) Status() map[StepStatus]int {
	m := map[StepStatus]int{}
	for _, n := range x.steps() {
		m[stepStatus(n)]++
	}
	return m
}

// Done reports whether every step has reached a terminal state (done/failed/
// blocked) — i.e. the process has nothing left to do.
func (x *Executor) Done() bool {
	for _, n := range x.steps() {
		switch stepStatus(n) {
		case StepDone, StepFailed, StepBlocked:
		default:
			return false
		}
	}
	return true
}

// ── plan construction (so apps + tests build a plan subgraph without hand-wiring) ──

// NewPlan creates a `plan` node that `decomposes` into one `step` per label, all
// in a dedicated process namespace ("proc:<planID>"). Dependencies are added
// with DependStep. Returns the plan id and a label→stepID map.
func (e *Engine) NewPlan(label string, stepLabels []string) (planID string, stepIDs map[string]string, err error) {
	plan, err := e.AddNode(Node{Kind: KindPlan, Label: label, Base: 0.5, Prov: Provenance{Source: "plan"}})
	if err != nil {
		return "", nil, err
	}
	ns := "proc:" + plan.ID
	plan.Namespace = ns
	_ = e.Store().PutNode(plan)
	stepIDs = make(map[string]string, len(stepLabels))
	for _, sl := range stepLabels {
		s, e2 := e.AddNode(Node{Kind: KindStep, Namespace: ns, Label: sl, Base: 0.4,
			Attrs: map[string]string{stepStatusAttr: string(StepPending)}, Prov: Provenance{Source: "plan"}})
		if e2 != nil {
			return "", nil, e2
		}
		stepIDs[sl] = s.ID
		if _, e3 := e.AddEdge(Edge{Kind: EdgeDecomposes, Namespace: ns, From: plan.ID, To: s.ID, Weight: 0.7}); e3 != nil {
			return "", nil, e3
		}
	}
	return plan.ID, stepIDs, nil
}

// DependStep records that stepID depends on prereqID (EdgeDependsOn): stepID
// will not enter the frontier until prereqID is done.
func (e *Engine) DependStep(stepID, prereqID string) error {
	_, err := e.AddEdge(Edge{Kind: EdgeDependsOn, From: stepID, To: prereqID, Weight: 0.8})
	return err
}
