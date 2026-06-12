// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "jip-conformance",
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "conformance",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")]
        ),
    ]
)
