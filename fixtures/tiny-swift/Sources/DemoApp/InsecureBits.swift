import Foundation
import WebKit
import UIKit

enum InsecureBits {
  static func storeToken() {
    let token = "live-session-token-value"
    UserDefaults.standard.set(token, forKey: "authToken")
    let shared = UserDefaults(suiteName: "group.com.example.demo")
    shared?.set(token, forKey: "refreshToken")
  }

  static func keychainAlways() {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccessible as String: kSecAttrAccessibleAlways,
    ]
    SecItemAdd(query as CFDictionary, nil)
  }

  static func pasteSecret() {
    let password = "hunter2-secret"
    UIPasteboard.general.string = password
  }

  static func logSecret(token: String) {
    print("authorization token \(token)")
  }

  static func weakHash(_ data: Data) -> [UInt8] {
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
    return digest
  }

  static func cleartext() -> URL? {
    URL(string: "http://api.internal.example.net/v1/session")
  }

  static func shellOut() {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/zsh")
  }
}

final class BridgeController: NSObject, WKScriptMessageHandler {
  func userContentController(
    _ userContentController: WKUserContentController,
    didReceive message: WKScriptMessage
  ) {}

  func attach(to controller: WKUserContentController) {
    controller.add(self, name: "nativeBridge")
    webView?.evaluateJavaScript("window.ready = true")
  }

  var webView: WKWebView?
}

final class TrustingSession: NSObject, URLSessionDelegate {
  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    if let trust = challenge.protectionSpace.serverTrust {
      completionHandler(.useCredential, URLCredential(trust: trust))
    }
  }
}

struct DemoApp: App {
  var body: some Scene {
    WindowGroup {
      ContentView()
        .onOpenURL { url in
          handle(url)
        }
    }
  }

  func handle(_ url: URL) {}
}
