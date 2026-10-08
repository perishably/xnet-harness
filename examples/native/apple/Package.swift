// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "XNETSourceCore",
    platforms: [.macOS(.v13), .iOS("26.4")],
    products: [
        .library(name: "XNETSourceCore", targets: ["XNETSourceCore"]),
        .library(name: "XNETRemote", targets: ["XNETRemote"]),
    ],
    targets: [
        .target(name: "XNETSourceCore", path: "XNETHome/SourceCore"),
        .target(name: "XNETRemote", path: "XNETHome/Remote"),
        .testTarget(name: "XNETSourceCoreTests", dependencies: ["XNETSourceCore"],
            path: "XNETHomeTests")
    ])
