import Foundation

// INTENTIONAL WEAKNESSES FOR FIXTURE / REMEDIATION SMOKE TESTS
enum Secrets {
    static let apiKey = "hardcoded_swift_api_key_value_123456"
}

func storeToken(_ token: String) {
    UserDefaults.standard.set(token, forKey: "authToken")
}

func debugAuth(_ token: String) {
    print("token \(token)")
}

let insecure = "http://api.example.com/v1/login"
