import Foundation
import CryptoKit

enum SafeBits {
  static func storePreference() {
    UserDefaults.standard.set(true, forKey: "hasSeenOnboarding")
  }

  static func hash(_ data: Data) -> SHA256Digest {
    SHA256.hash(data: data)
  }

  static func httpsEndpoint() -> URL? {
    URL(string: "https://api.example.com/v1/session")
  }
}
