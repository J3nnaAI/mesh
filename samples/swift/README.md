# J3nna Mesh — Swift joiner sample

The full authorized-collaboration loop in Swift, mirroring `samples/python/joiner.py` and the Go sample:

    enroll with the console   ->  receive a signed grant + the authority root
    discover a 'rooms' peer    ->  the room agent, found over gossip (not hardcoded)
    join its room + post       ->  collaborate, all authorized, under one trace

It is the `joiner` executable target of the Swift SDK package at
[`../../sdks/swift`](../../sdks/swift), built on the `J3nnaMesh` library.

## Run

```sh
export PATH=$PATH:/opt/swift/usr/bin
cd ../../sdks/swift
swift run joiner
```

Start the console and a room agent first, then approve the enrollment in the console (match the
out-of-band code the joiner prints).

## Configuration (environment)

| Var | Default | Meaning |
| --- | --- | --- |
| `SAMPLE_CONSOLE`   | `http://127.0.0.1:18455` | enrollment console base URL |
| `SAMPLE_SEEDS`     | `http://127.0.0.1:18482` | comma-separated gossip seed peers |
| `SAMPLE_ROOM`      | `lobby`                  | room to join/post |
| `SAMPLE_NAME`      | `swift-joiner`           | client name + room alias |
| `SAMPLE_IDENTITY`  | `swift-joiner.id`        | identity file path (created on first run) |
| `SAMPLE_ADVERTISE` | `http://127.0.0.1:1/`    | advertised endpoint (client-only, need not be reachable) |
