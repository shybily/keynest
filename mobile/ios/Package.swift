// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "KeynestClient",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "KeynestClient", targets: ["KeynestClient"])
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0")
    ],
    targets: [
        .target(
            name: "KeynestClient",
            dependencies: [
                .product(name: "BigInt", package: "BigInt")
            ]
        ),
        .testTarget(name: "KeynestClientTests", dependencies: ["KeynestClient"])
    ]
)
