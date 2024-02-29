// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftFindMy",
    platforms: [.macOS(.v10_15), .iOS(.v13)], // Due to the use of the CryptoKit framework
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftFindMy",
            targets: ["SwiftFindMy"])
    ],
    dependencies: [
        .package(url: "https://github.com/leif-ibsen/SwiftECC.git", .upToNextMajor(from: "5.3.0")),
        // other dependencies
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.1.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftFindMy",
            dependencies: ["SwiftECC"]),

        .testTarget(
            name: "SwiftFindMyTests",
            dependencies: ["SwiftFindMy"]),
    ]
)
