// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "WepoWallet",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "WepoWallet",
            targets: ["WepoWallet"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.8.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", from: "2.1.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "WepoWallet",
            dependencies: [
                "Alamofire",
                "CryptoSwift", 
                "Base58Swift",
                "BigInt",
                .product(name: "Crypto", package: "swift-crypto")
            ]),
        .testTarget(
            name: "WepoWalletTests",
            dependencies: ["WepoWallet"]),
    ]
)