// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
//
// A J3nna Mesh peer in C#/.NET — the full authorized-collaboration loop, mirroring samples/joiner (Go) and
// the Python reference:
//
//     enroll with the console   ->  receive a signed grant + the authority root
//     discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
//     join its room + post       ->  collaborate, all authorized, with one trace for telemetry
//
// Run the console and a room-agent first, then this; approve the enrollment in the console (match the
// out-of-band code it prints). Built on the J3nnaMesh SDK.

using System.Text.Json;
using J3nnaMesh;

static string Env(string k, string d) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : d;

var console = Env("SAMPLE_CONSOLE", "http://127.0.0.1:18455");
var seeds = Env("SAMPLE_SEEDS", "http://127.0.0.1:18482")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
var room = Env("SAMPLE_ROOM", "lobby");
var name = Env("SAMPLE_NAME", "csharp-joiner");
var idPath = Env("SAMPLE_IDENTITY", "csharp-joiner.id");
// A client-only peer: it polls history, so its advertised endpoint need not be reachable.
var endpoint = Env("SAMPLE_ADVERTISE", "http://127.0.0.1:1/");

Console.WriteLine($"joiner: enrolling with console {console} …");
var enrolled = Enroll.Run(console, name, idPath,
    onOob: o => Console.WriteLine($"joiner: APPROVE this enrollment in the console — out-of-band code {o}"));
var ident = enrolled.Identity;
var grant = enrolled.Grant;
var root = enrolled.Root;
var grantId = grant.GetProperty("id").GetString()!;
Console.WriteLine($"joiner: enrolled — grant {grantId[..Math.Min(8, grantId.Length)]}…");

var record = Discovery.BuildPresence(ident, grant, endpoint, new[] { "sample" });
string? host = null;
for (var i = 0; i < 30; i++)
{
    var peers = Discovery.Discover(seeds, record, root: root, wantCap: "rooms");
    if (peers.Count > 0)
    {
        host = peers[0].Mcp;
        break;
    }
    Thread.Sleep(1000);
}
if (host == null)
{
    Console.WriteLine("joiner: no authorized room agent discovered on the mesh");
    Environment.Exit(1);
}
Console.WriteLine($"joiner: discovered room agent at {host} — joining #{room}");

// One trace for the whole session — so a telemetry backend stitches these calls into one operation.
var trace = Wire.NewTraceparent();
Rooms.Join(host, ident, room, name, endpoint, presenter: record, trace: trace);
Rooms.Post(host, ident, room, $"hello from {name} — .NET peer, authorized and present.",
    presenter: record, trace: trace);
var hist = Rooms.History(host, ident, room, since: 0, presenter: record, trace: trace);

var count = 0;
var msgs = hist.TryGetProperty("messages", out var ms) && ms.ValueKind == JsonValueKind.Array
    ? ms.EnumerateArray().ToList()
    : new List<JsonElement>();
Console.WriteLine($"joiner: #{room} has {msgs.Count} message(s):");
foreach (var m in msgs)
{
    var text = m.TryGetProperty("text", out var t) ? t.GetString() ?? "" : "";
    if (string.IsNullOrWhiteSpace(text)) continue;
    var from = m.TryGetProperty("from", out var f) ? f.GetString() ?? "" : "";
    Console.WriteLine($"joiner:   {from[..Math.Min(8, from.Length)]}: {text}");
    count++;
}
Console.WriteLine($"joiner: collaboration loop complete — trace {trace.Substring(3, 8)}");
