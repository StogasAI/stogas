// swift-tools-version: 6.2
import PackageDescription

#if os(Linux)
let native: Target = .binaryTarget(name: "CStogas", path: "CStogas.artifactbundle")
#else
let native: Target = .binaryTarget(name: "CStogas", path: "CStogas.xcframework")
#endif

let package = Package(
    name: "Stogas",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [.library(name: "Stogas", targets: ["Stogas"])],
    targets: [
        native,
        .target(name: "Stogas", dependencies: ["CStogas"], linkerSettings: [
            .linkedLibrary("dl", .when(platforms: [.linux])),
            .linkedLibrary("pthread", .when(platforms: [.linux])),
            .linkedLibrary("m", .when(platforms: [.linux])),
            .linkedFramework("Security", .when(platforms: [.macOS, .iOS])),
            .linkedFramework("CoreFoundation", .when(platforms: [.macOS, .iOS])),
        ]),
        .testTarget(name: "StogasTests", dependencies: ["Stogas"]),
    ]
)
