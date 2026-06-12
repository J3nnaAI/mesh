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

// Command monitor is a live, CLI-only view of all activity on a J3nna Mesh — a "top" for the mesh. It is
// the reference telemetry consumer: it runs a collector that mesh peers POST their events to, and renders a
// live terminal dashboard — a roster of who's present (level) above a scrolling, color-coded stream of every
// touch (edge): tool calls, room joins/posts, peer admissions and rejections.
//
// It is entirely OPTIONAL — the mesh runs fine without it. Point peers at it by setting, on each peer,
//
//	JIP_TELEMETRY_URL=http://127.0.0.1:19000/events
//
// then run this. Part of J3nna Mesh; see docs/. Pure standard library.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// event mirrors jip.Event on the wire (kept local so the monitor stays a zero-dependency, stdlib-only tool).
type event struct {
	Ts      int64  `json:"ts"`
	Node    string `json:"node"`
	Kind    string `json:"kind"`
	Peer    string `json:"peer"`
	Tool    string `json:"tool"`
	Room    string `json:"room"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	Trace   string `json:"trace"`
	Span    string `json:"span"`
	DurMs   int64  `json:"dur_ms"`
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
)

type peerStat struct {
	last   int64
	events int
}

var (
	mu        sync.Mutex
	ring      []event
	roster    = map[string]*peerStat{}
	counts    = map[string]int{}
	total     int
	start     = time.Now()
	isTTY     bool   // a real terminal → flicker-free repaint; otherwise (pipe/Docker logs) → append-only lines
	prevFrame string // last painted frame — repaint only when it actually changes
	lastStat  int    // event total at the last printed status summary (non-terminal output)
)

const ringMax = 400

func ingest(e event) {
	mu.Lock()
	defer mu.Unlock()
	if e.Ts == 0 {
		e.Ts = time.Now().UnixMilli()
	}
	ring = append(ring, e)
	if len(ring) > ringMax {
		ring = ring[len(ring)-ringMax:]
	}
	total++
	counts[e.Kind]++
	if !isTTY {
		fmt.Print(formatEventLine(e)) // not a terminal: stream clean append-only lines, no repaint
	}
	for _, id := range []string{e.Node, e.Peer} {
		if id == "" {
			continue
		}
		ps := roster[id]
		if ps == nil {
			ps = &peerStat{}
			roster[id] = ps
		}
		if e.Ts > ps.last {
			ps.last = e.Ts
		}
		ps.events++
	}
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func kindColor(kind, outcome string) (string, string) {
	if outcome == "denied" {
		return red, "DENY"
	}
	if outcome == "error" {
		return yellow, " ERR"
	}
	switch kind {
	case "call":
		return cyan, "CALL"
	case "room":
		return green, "ROOM"
	case "admit":
		return green, " ADM"
	case "reject":
		return red, " REJ"
	case "gossip":
		return gray, "GOSS"
	case "grant":
		return blue, "GRNT"
	case "presence":
		return gray, "PRES"
	}
	return reset, strings.ToUpper(short(kind))
}

func render() {
	mu.Lock()
	defer mu.Unlock()
	var b strings.Builder

	// ── header: title + live roster (level) ──
	b.WriteString(fmt.Sprintf("%s  J3nna Mesh — live monitor%s   %s%d events%s\n",
		bold, reset, dim, total, reset))
	b.WriteString(gray + "  ──────────────────────────────────────────────────────────────────────────\n" + reset)

	ids := make([]string, 0, len(roster))
	for id := range roster {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return roster[ids[i]].last > roster[ids[j]].last })
	now := time.Now().UnixMilli()
	b.WriteString(fmt.Sprintf("%s  peers (%d):%s ", bold, len(ids), reset))
	for i, id := range ids {
		if i >= 8 {
			b.WriteString(dim + fmt.Sprintf("+%d more", len(ids)-8) + reset)
			break
		}
		age := (now - roster[id].last) / 1000
		c := green
		if age > 15 {
			c = gray
		}
		b.WriteString(fmt.Sprintf("%s%s%s(%d) ", c, short(id), reset, roster[id].events))
	}
	b.WriteString("\n")

	// counts by kind
	b.WriteString(dim + "  ")
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		b.WriteString(fmt.Sprintf("%s=%d  ", k, counts[k]))
	}
	b.WriteString(reset + "\n")
	b.WriteString(gray + "  ──────────────────────────────────────────────────────────────────────────\n" + reset)

	// ── event stream (edge): last ~28 touches, newest at the bottom ──
	startIdx := 0
	if len(ring) > 28 {
		startIdx = len(ring) - 28
	}
	for _, e := range ring[startIdx:] {
		b.WriteString(formatEventLine(e))
	}

	// Home + overwrite each line to end-of-line (\033[K) + erase below (\033[J) — no full-screen wipe.
	// Then: skip the repaint entirely when the frame is byte-identical to the last (an idle screen never
	// repaints), and wrap the change in a SYNCHRONIZED UPDATE (DEC private mode 2026) so a supporting
	// terminal swaps the whole frame atomically instead of tearing line-by-line. Together these end the
	// flicker; on a terminal that ignores 2026 the diff-skip still removes the idle strobe.
	frame := "\033[H" + strings.ReplaceAll(b.String(), "\n", "\033[K\n") + "\033[J"
	if frame == prevFrame {
		return
	}
	prevFrame = frame
	fmt.Print("\033[?2026h" + frame + "\033[?2026l")
}

// formatEventLine renders one event as a single coloured line (used by the live stream and, when output is
// piped/not a terminal, as the append-only log line).
func formatEventLine(e event) string {
	c, tag := kindColor(e.Kind, e.Outcome)
	ts := time.UnixMilli(e.Ts).Format("15:04:05.000")
	subject := logSafe(e.Tool)
	if e.Room != "" {
		subject = "#" + logSafe(e.Room)
	}
	dur := ""
	if e.DurMs > 0 {
		dur = fmt.Sprintf(" %dms", e.DurMs)
	}
	arrow := ""
	if e.Peer != "" {
		arrow = gray + "→" + reset + " " + short(logSafe(e.Peer))
	}
	return fmt.Sprintf("  %s%s%s  %s%s%s  %s%-8s%s %s  %s%s%s%s\n",
		gray, ts, reset, c, tag, reset, bold, short(logSafe(e.Node)), reset, arrow, c, subject, reset, dim+dur+" "+logSafe(e.Detail)+reset)
}

// statusLine is a compact one-line roster/counts summary for non-terminal output. Returns "" if nothing has
// happened since the last summary, so an idle monitor stays quiet.
func statusLine() string {
	mu.Lock()
	defer mu.Unlock()
	if total == lastStat {
		return ""
	}
	lastStat = total
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var c strings.Builder
	for _, k := range kinds {
		fmt.Fprintf(&c, " %s=%d", logSafe(k), counts[k])
	}
	return fmt.Sprintf("%s  ── %d peers ·%s · %d events ──%s\n", gray, len(roster), c.String(), total, reset)
}

func main() {
	addr := os.Getenv("MONITOR_ADDR")
	if addr == "" {
		addr = "127.0.0.1:19000"
	}
	if fi, _ := os.Stdout.Stat(); fi != nil && fi.Mode()&os.ModeCharDevice != 0 {
		isTTY = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var e event
		if json.NewDecoder(r.Body).Decode(&e) == nil {
			ingest(e)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// /snapshot — a JSON dump of the current state, for scripted checks (the live view is the terminal render).
	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ids := make([]string, 0, len(roster))
		for id := range roster {
			ids = append(ids, id)
		}
		recent := ring
		if len(recent) > 50 {
			recent = recent[len(recent)-50:]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": total, "counts": counts, "peers": ids, "recent": recent,
		})
	})

	if isTTY {
		// Alternate screen + hidden cursor: a flicker-free, self-restoring live dashboard.
		fmt.Print("\033[?1049h\033[?25l")
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() { <-sig; fmt.Print("\033[?25h\033[?1049l"); os.Exit(0) }()
		go func() {
			t := time.NewTicker(250 * time.Millisecond)
			defer t.Stop()
			for range t.C {
				render()
			}
		}()
	} else {
		// Piped / Docker logs: ingest already streams one clean line per event; add an occasional compact
		// status summary so the totals are visible without painting a dashboard every frame.
		go func() {
			t := time.NewTicker(8 * time.Second)
			defer t.Stop()
			for range t.C {
				if s := statusLine(); s != "" {
					fmt.Print(s)
				}
			}
		}()
	}

	fmt.Fprintf(os.Stderr, "mesh monitor: collecting on http://%s/events  (set JIP_TELEMETRY_URL on peers)\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "monitor:", err)
		os.Exit(1)
	}
}

// logSafe strips CR/LF and other C0 control characters so a malicious peer cannot forge/break output lines.
func logSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		if r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
