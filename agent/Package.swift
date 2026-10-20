// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Altiward",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "altiward-agent", targets: ["AltiwardDaemon"]),
        .executable(name: "altiward-hook", targets: ["AltiwardHook"]),
        .library(name: "AltiwardCore", targets: ["AltiwardCore"]),
    ],
    targets: [
        .target(
            name: "AltiwardCore",
            linkerSettings: [
                .linkedLibrary("sqlite3"),
                .linkedFramework("IOKit"),
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(name: "AltiwardDaemon", dependencies: ["AltiwardCore"]),
        .executableTarget(name: "AltiwardHook", dependencies: ["AltiwardCore"]),
        .testTarget(name: "AltiwardCoreTests", dependencies: ["AltiwardCore"]),
    ]
)
