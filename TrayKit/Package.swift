// swift-tools-version:5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
import PackageDescription

// libtray_ffi.a is built by `cargo build -p tray-ffi --release` into the workspace's target/.
let rustLib = "\(Context.packageDirectory)/../target/release"

let package = Package(
    name: "TrayKit",
    platforms: [.macOS(.v13)],
    products: [
        // The menu-bar UI, with no Rust in it: a consumer can use it on its own.
        .library(name: "TrayKit", targets: ["TrayKit"]),
        // tray-core's verified tabs, through the C ABI.
        .library(name: "TrayCoreBridge", targets: ["TrayCoreBridge"]),
    ],
    targets: [
        .target(
            name: "CTrayCore",
            linkerSettings: [.unsafeFlags(["-L", rustLib])]
        ),
        .target(name: "TrayCoreBridge", dependencies: ["CTrayCore"]),
        .target(name: "TrayKit"),
        .testTarget(name: "TrayKitTests", dependencies: ["TrayKit", "TrayCoreBridge"]),
    ]
)
