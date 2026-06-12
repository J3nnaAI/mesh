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

// Version is the kernel's semantic version.
//
// v1.0.0 is the LOCKED surface: the mechanism is complete for every capability we
// have validated — the typed bi-temporal graph substrate, defocus retrieval, the
// reasoning-workspace schema, and the process executor INCLUDING step-to-step data
// flow. It is stdlib-only, WASM-safe (validated running inside wazero), and green.
//
// "Locked" does not mean frozen forever — it means: changes after v1.0 are ADDITIVE
// (new methods, new node/edge kinds) and non-breaking, unless a measured need forces
// a major bump. Deferred mechanism (async/parallel execution, structured step I/O,
// mesh step-claim handoff, a shared-memory org tier) is listed with reasons in
// LOCK.md and is purely additive when a validated capability demands it. The
// discriminating rule for what belongs here: a gap is kernel-level iff no StepRunner,
// Tool, Controller, or thought-process could supply it from the policy layer.
const Version = "1.0.0"
