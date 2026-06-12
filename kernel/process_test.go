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

// The executor is a kernel primitive, so it gets kernel-grade tests: pure, no
// LLM, exercising the exact properties the control plane (§5e) and the process
// pillar (§5b) depend on — dependency ordering, frontier-in-graph persistence,
// single-stepping, breakpoint pause/resume, transitive failure-blocking, and
// live mid-flight editing.

import (
	"context"
	"testing"
)

// buildDiamond wires a classic diamond DAG: A and B are roots; C depends on both;
// D depends on C.
func buildDiamond(t *testing.T, e *Engine) (string, map[string]string) {
	t.Helper()
	planID, ids, err := e.NewPlan("diamond", []string{"A", "B", "C", "D"})
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	for _, d := range [][2]string{{"C", "A"}, {"C", "B"}, {"D", "C"}} {
		if err := e.DependStep(ids[d[0]], ids[d[1]]); err != nil {
			t.Fatalf("DependStep %v: %v", d, err)
		}
	}
	return planID, ids
}

func statusOf(e *Engine, id string) StepStatus {
	n, _ := e.Store().GetNode(id)
	return stepStatus(n)
}

func TestExecutorOrderingAndPersistence(t *testing.T) {
	e := Open(Options{})
	planID, ids := buildDiamond(t, e)
	var order []string
	x := e.NewExecutor(planID, RunnerFunc(func(_ context.Context, s Node, _ []StepInput) StepOutcome {
		order = append(order, s.Label)
		return StepOutcome{Status: StepDone, Effect: s.Label + "-effect"}
	}))
	res, err := x.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res) != 4 {
		t.Fatalf("ran %d steps, want 4 (%v)", len(res), order)
	}
	pos := map[string]int{}
	for i, l := range order {
		pos[l] = i
	}
	if !(pos["A"] < pos["C"] && pos["B"] < pos["C"] && pos["C"] < pos["D"]) {
		t.Fatalf("execution order violates dependencies: %v", order)
	}
	if !x.Done() {
		t.Fatal("expected Done after full run")
	}
	// frontier-in-graph: every step's status + effect persisted on the node
	for _, l := range []string{"A", "B", "C", "D"} {
		n, _ := e.Store().GetNode(ids[l])
		if stepStatus(n) != StepDone {
			t.Fatalf("step %s persisted status=%s, want done", l, stepStatus(n))
		}
		if n.Attrs[stepEffectAttr] == "" {
			t.Fatalf("step %s effect not persisted", l)
		}
	}
}

func TestExecutorSingleStep(t *testing.T) {
	e := Open(Options{})
	planID, _ := buildDiamond(t, e)
	x := e.NewExecutor(planID, RunnerFunc(func(_ context.Context, _ Node, _ []StepInput) StepOutcome {
		return StepOutcome{Status: StepDone}
	}))
	ctx := context.Background()
	n := 0
	for {
		if _, ok := x.Step(ctx); !ok {
			break
		}
		if n++; n > 10 {
			t.Fatal("single-step loop runaway")
		}
	}
	if n != 4 {
		t.Fatalf("stepped %d times, want 4", n)
	}
	if !x.Done() {
		t.Fatal("expected Done after single-stepping")
	}
}

func TestExecutorBreakpointResume(t *testing.T) {
	e := Open(Options{})
	planID, ids := buildDiamond(t, e)
	ran := map[string]bool{}
	x := e.NewExecutor(planID, RunnerFunc(func(_ context.Context, s Node, _ []StepInput) StepOutcome {
		ran[s.Label] = true
		return StepOutcome{Status: StepDone}
	}))
	tripped := false
	x.WithController(ControlFunc(func(_ context.Context, s Node, _ *Executor) ControlDecision {
		if s.ID == ids["C"] && !tripped { // breakpoint on C, once
			tripped = true
			return Pause
		}
		return Proceed
	}))
	ctx := context.Background()
	if _, err := x.Run(ctx); err != ErrPaused {
		t.Fatalf("expected ErrPaused at breakpoint, got %v", err)
	}
	if !ran["A"] || !ran["B"] {
		t.Fatal("A and B should have run before the breakpoint")
	}
	if ran["C"] || ran["D"] {
		t.Fatal("C and D must not run at the breakpoint")
	}
	if _, err := x.Run(ctx); err != nil { // resume
		t.Fatalf("resume Run: %v", err)
	}
	if !ran["C"] || !ran["D"] {
		t.Fatal("C and D should run after resume")
	}
	if !x.Done() {
		t.Fatal("expected Done after resume")
	}
}

func TestExecutorFailureBlocksDependents(t *testing.T) {
	e := Open(Options{})
	planID, ids := buildDiamond(t, e)
	x := e.NewExecutor(planID, RunnerFunc(func(_ context.Context, s Node, _ []StepInput) StepOutcome {
		if s.Label == "B" {
			return StepOutcome{Status: StepFailed, Effect: "boom"}
		}
		return StepOutcome{Status: StepDone}
	}))
	if _, err := x.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if statusOf(e, ids["A"]) != StepDone {
		t.Fatalf("A=%s, want done", statusOf(e, ids["A"]))
	}
	if statusOf(e, ids["B"]) != StepFailed {
		t.Fatalf("B=%s, want failed", statusOf(e, ids["B"]))
	}
	if statusOf(e, ids["C"]) != StepBlocked { // depends on failed B
		t.Fatalf("C=%s, want blocked", statusOf(e, ids["C"]))
	}
	if statusOf(e, ids["D"]) != StepBlocked { // depends on blocked C (transitive)
		t.Fatalf("D=%s, want blocked", statusOf(e, ids["D"]))
	}
	if !x.Done() {
		t.Fatal("expected Done (all steps terminal)")
	}
}

func TestExecutorLiveEditWhilePaused(t *testing.T) {
	e := Open(Options{})
	planID, ids := buildDiamond(t, e)
	ran := map[string]bool{}
	x := e.NewExecutor(planID, RunnerFunc(func(_ context.Context, s Node, _ []StepInput) StepOutcome {
		ran[s.Label] = true
		return StepOutcome{Status: StepDone}
	}))
	tripped := false
	x.WithController(ControlFunc(func(_ context.Context, s Node, _ *Executor) ControlDecision {
		if s.ID == ids["D"] && !tripped {
			tripped = true
			return Pause
		}
		return Proceed
	}))
	ctx := context.Background()
	x.Run(ctx) // runs A,B,C then pauses before D
	if !ran["C"] || ran["D"] {
		t.Fatalf("expected to pause before D (ran=%v)", ran)
	}
	// live edit: an attached operator removes D from the running process
	if err := e.Tombstone(ids["D"], Tombstone{Reason: "operator removed", Authority: "test"}); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if _, err := x.Run(ctx); err != nil {
		t.Fatalf("resume after edit: %v", err)
	}
	if ran["D"] {
		t.Fatal("D was tombstoned mid-flight; it must not run")
	}
	if !x.Done() {
		t.Fatal("expected Done after the live edit")
	}
}

func TestDeleteNode(t *testing.T) {
	e := Open(Options{})
	// Hard-delete is for ephemeral operational records only; durable knowledge
	// is retired via Tombstone (see TestDeleteNode_EnforcesDurableInvariant).
	a, _ := e.AddNode(Node{Kind: KindEpisode, Body: "x", Ephemeral: true})
	b, _ := e.AddNode(Node{Kind: KindEpisode, Body: "y", Ephemeral: true})
	_, _ = e.AddEdge(Edge{Kind: EdgeRelational, From: a.ID, To: b.ID})
	if err := e.DeleteNode(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Store().GetNode(a.ID); ok {
		t.Fatal("node should be hard-deleted")
	}
	if len(e.Store().EdgesFrom(a.ID)) != 0 || len(e.Store().EdgesTo(b.ID)) != 0 {
		t.Fatal("incident edges should be removed with the node")
	}
}
