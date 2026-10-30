// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "Sentinel",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "SentinelAgent", targets: ["SentinelAgent"]),
        .executable(name: "SentinelMenuBar", targets: ["SentinelMenuBar"]),
    ],
    targets: [
        .target(name: "SentinelShared"),
        .executableTarget(name: "SentinelAgent", dependencies: ["SentinelShared"]),
        .executableTarget(name: "SentinelMenuBar", dependencies: ["SentinelShared"]),
    ]
)
