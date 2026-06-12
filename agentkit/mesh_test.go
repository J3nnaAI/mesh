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

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitUp(t *testing.T, url string) {
	t.Helper()
	for i := 0; i < 80; i++ {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("peer never came up: %s", url)
}

// TestMeshTwoPeerBrigadier proves a persona is a real first-class mesh peer: Jade hosts the
// brigadier room, a second peer (Wes) joins it remotely, both post, and Jade reads the shared log.
func TestMeshTwoPeerBrigadier(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pa, pb := freePort(t), freePort(t)
	advA := fmt.Sprintf("http://127.0.0.1:%d", pa)
	advB := fmt.Sprintf("http://127.0.0.1:%d", pb)

	jade, err := Open(ctx, Options{Advertise: advA, Listen: fmt.Sprintf("127.0.0.1:%d", pa), Caps: []string{"mesh", "persona"}})
	if err != nil {
		t.Fatalf("open jade: %v", err)
	}
	defer jade.Close()
	wes, err := Open(ctx, Options{Advertise: advB, Listen: fmt.Sprintf("127.0.0.1:%d", pb), Caps: []string{"mesh"}})
	if err != nil {
		t.Fatalf("open wes: %v", err)
	}
	defer wes.Close()

	waitUp(t, advA+"/whoami")
	waitUp(t, advB+"/whoami")

	if jade.ID() == "" || jade.ID() == wes.ID() {
		t.Fatalf("peers must have distinct non-empty ids: jade=%q wes=%q", jade.ID(), wes.ID())
	}

	// Jade hosts #brigadier.
	if err := jade.CreateRoom(ctx, "brigadier", "Jade", false); err != nil {
		t.Fatalf("create room: %v", err)
	}
	// Wes joins Jade's room (remote — at Jade's /mcp).
	roster, err := wes.JoinRoom(ctx, jade.SelfMCP(), "brigadier", "Wes")
	if err != nil {
		t.Fatalf("join room: %v", err)
	}
	if len(roster) < 2 {
		t.Fatalf("roster after join should have >=2 members, got %d: %+v", len(roster), roster)
	}

	// Both post.
	if err := jade.Post(ctx, "", "brigadier", "Jade here, brigadier."); err != nil {
		t.Fatalf("jade post: %v", err)
	}
	if err := wes.Post(ctx, jade.SelfMCP(), "brigadier", "Wes reporting in."); err != nil {
		t.Fatalf("wes post: %v", err)
	}

	// Jade reads the shared history.
	msgs, err := jade.History(ctx, "", "brigadier", 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var all strings.Builder
	for _, mm := range msgs {
		all.WriteString(mm.Text)
		all.WriteString("\n")
	}
	if !strings.Contains(all.String(), "Jade here") || !strings.Contains(all.String(), "Wes reporting") {
		t.Fatalf("history missing both posts; got:\n%s", all.String())
	}

	// The room snapshot witnesses both members.
	rooms := jade.Rooms()
	if len(rooms) != 1 || len(rooms[0].Members) < 2 {
		t.Fatalf("snapshot should show 1 room with >=2 members, got %+v", rooms)
	}
}
