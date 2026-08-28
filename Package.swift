// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "SwiftXMPP",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SwiftXMPP", targets: ["SwiftXMPP"]),
        // A thin command-line harness, so the stack can be driven against a
        // real server and a real OMEMO peer from a script. Not shipped; it
        // exists to make the interop test runnable.
        .executable(name: "xmpp-cli", targets: ["XMPPCLI"]),
    ],
    // No dependencies, deliberately. Everything here is the platform's own
    // CryptoKit and Foundation; a client library that drags a tree of packages
    // behind it costs its users bundle size they cannot see coming.
    targets: [
        .target(name: "SwiftXMPP"),
        .executableTarget(name: "XMPPCLI", dependencies: ["SwiftXMPP"]),
        .testTarget(name: "SwiftXMPPTests", dependencies: ["SwiftXMPP"]),
    ]
)
