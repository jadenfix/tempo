// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "TempoIOS",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "Tempo", targets: ["Tempo"]),
    ],
    targets: [
        .target(
            name: "Tempo",
            path: "Tempo",
            exclude: [
                "Info.plist",
                "TempoApp.swift",
                "BrowserShellView.swift",
                "ManagerPanelView.swift",
                "WebViewContainer.swift",
            ],
            resources: [
                .process("Resources"),
            ]
        ),
        .testTarget(
            name: "TempoShellTests",
            dependencies: ["Tempo"],
            path: "TempoTests"
        ),
    ]
)
