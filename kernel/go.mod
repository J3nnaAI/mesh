// Module kernel is a standalone, embeddable memory/knowledge-graph engine:
// a living, typed, bi-temporal activation graph with spreading-activation
// retrieval at tunable defocus. Stdlib-only and WASM-safe by invariant, so it
// runs server-side, in the browser (WASM), or on-device (gomobile) unchanged.
//
// It depends on nothing outside the standard library. Storage sits behind an
// interface; the default is an in-memory graph with JSON snapshotting.
module github.com/J3nnaAI/mesh/kernel

go 1.26.4
