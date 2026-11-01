import SwiftUI
import MFiKit

@main
struct CarPlayDeskApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("CarPlayDesk") {
            ContentView(model: model)
        }
        .windowResizability(.contentSize)
    }
}
