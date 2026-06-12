// swift-tools-version:5.9
// Copyright 2026 J3nna Technologies, LLC
// SPDX-License-Identifier: Apache-2.0
import PackageDescription

let package = Package(
    name: "J3nnaMesh",
    products: [
        .library(name: "J3nnaMesh", targets: ["J3nnaMesh"]),
        .executable(name: "joiner", targets: ["joiner"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "J3nnaMesh",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
        .executableTarget(
            name: "joiner",
            dependencies: ["J3nnaMesh"]
        ),
        .testTarget(
            name: "J3nnaMeshTests",
            dependencies: [
                "J3nnaMesh",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
    ]
)
