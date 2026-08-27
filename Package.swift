// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "SwiftXMPP",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SwiftXMPP", targets: ["SwiftXMPP"]),
    ],
    // No dependencies, deliberately. Everything here is the platform's own
    // CryptoKit and Foundation; a client library that drags a tree of packages
    // behind it costs its users bundle size they cannot see coming.
    targets: [
        .target(name: "SwiftXMPP"),
        .testTarget(name: "SwiftXMPPTests", dependencies: ["SwiftXMPP"]),
    ]
)
