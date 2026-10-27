/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import Foundation
import CryptoKit

public struct PKCEGenerator {

  // RFC 7636: code_verifier length MUST be between 43 and 128 characters
  private static let minCodeVerifierLength = 43
  private static let maxCodeVerifierLength = 128

  /// Default RFC7636-minimum-length code verifier (43 chars).
  public static func codeVerifier() -> String? {
    Self.codeVerifier(length: Self.minCodeVerifierLength)
  }

  /// RFC7636-conformant code verifier generator.
  /// - Parameter length: Must be in 43...128 (RFC7636).
  public static func codeVerifier(length: Int) -> String? {
    guard (minCodeVerifierLength...maxCodeVerifierLength).contains(length) else {
      return nil
    }
    return Self.generateRandomString(length: length)
  }

  public static func generateRandomData(length: Int = 48) -> Data? {
    var data = Data(count: length)
    let result = data.withUnsafeMutableBytes { mutableBytes in
      SecRandomCopyBytes(kSecRandomDefault, length, mutableBytes.baseAddress!)
    }
    
    guard result == errSecSuccess else {
      return nil // Random data generation failed
    }
    
    return data
  }
  
  /// RFC 7636 §4.1 unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~" (66 characters).
  static let unreservedCharacters: [Character] = Array(
    "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "-._~"
  )

  public static func generateRandomString(length: Int = 48) -> String? {
    uniformRandomString(length: length, alphabet: unreservedCharacters)
  }

  public static func generateRandomBase64String(length: Int = 48) -> String? {
    guard let randomString = uniformRandomString(length: length, alphabet: unreservedCharacters) else {
      return nil
    }
    return Data(randomString.utf8).base64EncodedString()
  }

  /// Samples `length` characters uniformly from `alphabet` using `SecRandomCopyBytes`.
  ///
  /// A plain `byte % alphabet.count` is biased whenever 256 is not a multiple of the alphabet size
  /// (with 66 characters, the first 58 would be ~1/3 more likely than the last 8). Rejection sampling
  /// discards bytes at or above the largest multiple of `alphabet.count` that fits in a byte (198 for
  /// 66 characters), so every remaining byte maps to each character equally often.
  ///
  /// - Returns: The random string, or `nil` if the system random number generator fails.
  static func uniformRandomString(length: Int, alphabet: [Character]) -> String? {
    precondition((1...256).contains(alphabet.count), "Alphabet must contain 1...256 characters")
    let rejectionLimit = 256 - 256 % alphabet.count

    var characters: [Character] = []
    characters.reserveCapacity(max(length, 0))
    while characters.count < length {
      guard let randomBytes = generateRandomData(length: length - characters.count) else {
        return nil
      }
      for byte in randomBytes where Int(byte) < rejectionLimit {
        characters.append(alphabet[Int(byte) % alphabet.count])
      }
    }
    return String(characters)
  }
  
  public static func generateCodeChallenge() -> String? {
    guard let randomVerifierString = generateRandomBase64String() else {
      return nil
    }
    
    if let data = randomVerifierString.data(using: .utf8) {
      let hashed = SHA256.hash(data: data)
      let challenge = Data(hashed).base64EncodedString()
      return challenge
    }
    return nil
  }
  
  public static func generateCodeChallenge(codeVerifier: String) -> String {
    guard let codeVerifierData = codeVerifier.data(using: .utf8) else {
      fatalError("Unable to convert code verifier to data.")
    }
    
    let hashedData = SHA256.hash(data: codeVerifierData)
    let base64Encoded = Data(hashedData).base64EncodedString()
    
    // URL safe encoding
    let codeChallenge = base64Encoded
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    
    return codeChallenge
  }
}
