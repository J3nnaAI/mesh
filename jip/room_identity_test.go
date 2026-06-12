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

package jip

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// mkMember builds a fresh signed presence record for a mesh member and returns its id + private key so the
// test can produce CallProofs as that member.
func mkMember(t *testing.T) (UUID, ed25519.PrivateKey, PresenceRecord) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	id, _ := newUUID()
	rec, err := sign(priv, PresencePayload{
		Protocol: ProtocolVersion, ID: id, PublicKey: pub, Endpoint: "http://m", MCPPath: "/mcp",
		HeartbeatUnix: time.Now().Unix(), ProtocolMajor: ProtocolMajor,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return id, priv, rec
}

// TestRoomIdentityBinding proves the room.* identity enforcement: a member cannot forge another member's
// `from` (the spoofable-`from` hole the room trust model documents but previously lacked). authorizeIdentity
// is what dispatch invokes for every IdentityBound room.* tool.
func TestRoomIdentityBinding(t *testing.T) {
	n, err := New(Options{Advertise: "http://self:1"})
	if err != nil {
		t.Fatal(err)
	}
	ownerID, ownerPriv, ownerRec := mkMember(t)
	attID, attPriv, attRec := mkMember(t)
	n.reg.merge([]PresenceRecord{ownerRec, attRec})
	s := &mcpServer{reg: n.reg}

	args := map[string]any{"room_id": "r1", "from": string(ownerID), "target": "someone"}

	// 1. Legit: the owner signs a call claiming from=owner → authorized.
	ok := SignCallProof(ownerID, ownerPriv, "room.approve", hashArgs(args), time.Now())
	if err := s.authorizeIdentity("room.approve", args, &ok); err != nil {
		t.Fatalf("legit owner call must be authorized, got: %v", err)
	}

	// 2. SPOOF: the attacker signs (proof.NodeID=attacker) but claims from=owner → MUST be rejected.
	spoof := SignCallProof(attID, attPriv, "room.approve", hashArgs(args), time.Now())
	if err := s.authorizeIdentity("room.approve", args, &spoof); err == nil {
		t.Fatal("SPOOF ACCEPTED: attacker forged from=owner and was authorized")
	}

	// 3. No proof at all → rejected.
	if err := s.authorizeIdentity("room.approve", args, nil); err == nil {
		t.Fatal("unsigned room call was authorized")
	}

	// 4. A signer who is not a known mesh member → rejected (even though from matches the signer).
	strangerID, strangerPriv, _ := mkMember(t) // deliberately NOT merged into the registry
	sArgs := map[string]any{"room_id": "r1", "from": string(strangerID)}
	sp := SignCallProof(strangerID, strangerPriv, "room.approve", hashArgs(sArgs), time.Now())
	if err := s.authorizeIdentity("room.approve", sArgs, &sp); err == nil {
		t.Fatal("non-member signer was authorized")
	}

	// 5. A node authenticating as ITSELF (hosting/managing its own room) is verified against its own key,
	// not the registry — otherwise a node could never create or manage its own room.
	selfID, selfPriv, _ := mkMember(t) // deliberately NOT in the registry
	self := &Self{ID: selfID, Priv: selfPriv, Pub: selfPriv.Public().(ed25519.PublicKey)}
	ss := &mcpServer{reg: n.reg, self: self}
	selfArgs := map[string]any{"room_id": "r1", "node_id": string(selfID)}
	selfProof := SignCallProof(selfID, selfPriv, "room.create", hashArgs(selfArgs), time.Now())
	if err := ss.authorizeIdentity("room.create", selfArgs, &selfProof); err != nil {
		t.Fatalf("a node managing its own room must be authorized, got: %v", err)
	}
	// but an attacker still can't impersonate that node's self-identity
	imposterProof := SignCallProof(attID, attPriv, "room.create", hashArgs(selfArgs), time.Now())
	if err := ss.authorizeIdentity("room.create", selfArgs, &imposterProof); err == nil {
		t.Fatal("attacker impersonated the host node's self-identity")
	}
}

// TestRoomFieldConfusion is the regression for Bug A: a call that sets one actor field to itself and the
// OTHER actor field to a victim (room.leave/join act on node_id; the gate had only checked from) must be
// rejected — every actor field is bound to the signer.
func TestRoomFieldConfusion(t *testing.T) {
	n, _ := New(Options{Advertise: "http://self:9"})
	attID, attPriv, attRec := mkMember(t)
	vicID, _, vicRec := mkMember(t)
	n.reg.merge([]PresenceRecord{attRec, vicRec})
	s := &mcpServer{reg: n.reg}
	// attacker signs as themselves but injects node_id=victim (the field room.leave actually consumes)
	args := map[string]any{"room_id": "r1", "from": string(attID), "node_id": string(vicID)}
	proof := SignCallProof(attID, attPriv, "room.leave", hashArgs(args), time.Now())
	if err := s.authorizeIdentity("room.leave", args, &proof); err == nil {
		t.Fatal("FIELD-CONFUSION: {from:self, node_id:victim} was authorized — attacker can evict the victim")
	}
}
