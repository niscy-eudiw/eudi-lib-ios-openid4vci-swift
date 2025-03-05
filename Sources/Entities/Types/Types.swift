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
import SwiftyJSON
import JOSESwift

public typealias JWT = String

public struct IssuanceResponseEncryptionSpec {
  public let jwk: JWK?
  public let privateKey: SecKey?
  public let algorithm: JWEAlgorithm
  public let encryptionMethod: JOSEEncryptionMethod
  
  public init(
    jwk: JWK? = nil,
    privateKey: SecKey?,
    algorithm: JWEAlgorithm,
    encryptionMethod: JOSEEncryptionMethod
  ) {
    self.jwk = jwk
    self.privateKey = privateKey
    self.algorithm = algorithm
    self.encryptionMethod = encryptionMethod
  }
}

public enum Proof: Codable {
  case jwt(JWT)
  
  public func type() -> ProofType {
    switch self {
    case .jwt:
      return .jwt
    }
  }
  
  // MARK: - Codable
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    
    if let jwt = try? container.decode(JWT.self) {
      self = .jwt(jwt)
    } else {
      throw DecodingError.typeMismatch(Proof.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Invalid proof type"))
    }
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    
    switch self {
    case .jwt(let jwt):
      try container.encode([
        "proof_type": "jwt",
        "jwt": jwt
      ])
    }
  }
  
  public func toDictionary() throws -> [String: String] {
    switch self {
    case .jwt(let jwt):
      return [
        "proof_type": "jwt",
        "jwt": jwt
      ]
    }
  }
}

public struct Scope: Codable {
  public let value: String
  
  public init(_ value: String?) throws {
    
    guard let value = value else {
      throw ValidationError.error(reason: "Scope cannot be nil")
    }
    
    guard !value.isEmpty else {
      throw ValidationError.error(reason: "Scope cannot be empty")
    }
    self.value = value
  }
}

public enum ContentType: String {
  case form = "application/x-www-form-urlencoded"
  case json = "application/json"
  
  public static let key = "Content-Type"
}

public struct AccessToken: Codable {
  public let value: String
  
  public init(value: String?) throws {
    guard let value else {
      throw ValidationError.error(reason: "Nil access token")
    }
    if value.isEmpty {
      throw ValidationError.error(reason: "Empty access token")
    }
    
    self.value = value
  }
}

public struct RefreshToken: Codable {
  public let value: String
  
  public init(value: String?) throws {
    guard let value else {
      throw ValidationError.error(reason: "Nil access token")
    }
    if value.isEmpty {
      throw ValidationError.error(reason: "Empty access token")
    }
    
    self.value = value
  }
}

public struct CNonce: Codable {
  public let value: String
  public let expiresInSeconds: Int?
  
  public init?(value: String?, expiresInSeconds: Int? = 5) {
    guard let value else { return nil }
    if value.isEmpty {
      return nil
    }
    
    self.value = value
    self.expiresInSeconds = expiresInSeconds
  }
}

public struct Nonce {
  public let value: String
  
  public init(value: String) {
    self.value = value
  }
}

public struct Claim: Codable {
  public let mandatory: Bool?
  public let display: [Display]?
  public let path: ClaimPath
  
  enum CodingKeys: String, CodingKey {
    case mandatory
    case display
    case path
  }
  
  public init() {
    self.mandatory = nil
    self.display = nil
    self.path = .init([])
  }
  
  public init(
    mandatory: Bool?,
    display: [Display]?,
    path: ClaimPath = .init([])
  ) {
    self.mandatory = mandatory
    self.display = display
    self.path = path
  }
  
  init(json: JSON) throws {
    mandatory = json["mandatory"].bool
    
    if let displayArray = json["display"].array {
      display = displayArray.map { displayJson in
        Display(json: displayJson)
      }
    } else {
      display = nil
    }
    
    self.path = try ClaimPath(json: json["path"])
  }
}

public struct DeferredIssuanceRequestTO: Codable {
  public let transactionId: String
  
  private enum CodingKeys: String, CodingKey {
    case transactionId = "transaction_id"
  }
  
  public init(transactionId: String) {
    self.transactionId = transactionId
  }
}

public enum TxCodeInputMode: String, Codable {
  case numeric
  case text
  
  public static func of(_ str: String) -> TxCodeInputMode {
    switch str {
    case "numeric": return .numeric
    case "text": return .text
    default: fatalError("Unsupported tx_code input method")
    }
  }
}

public struct TxCode: Codable {
  public let inputMode: TxCodeInputMode
  public let length: Int?
  public let description: String?
  
  public enum CodingKeys: String, CodingKey {
    case inputMode = "input_mode"
    case length
    case description
  }
  
  public init(
    inputMode: TxCodeInputMode,
    length: Int?,
    description: String?
  ) {
    self.inputMode = inputMode
    self.length = length
    self.description = description
  }
}

public enum InputModeTO: String, Codable {
  case text = "text"
  case numeric = "numeric"
}

public struct ProofsTO: Codable {
  public let jwtProofs: [String]?
  
  public enum CodingKeys: String, CodingKey {
    case jwtProofs = "jwt"
  }
  
  public init(jwtProofs: [String]? = nil) {
    guard !(jwtProofs?.isEmpty ?? true) else {
      fatalError("jwtProofs must be non-empty.")
    }
    self.jwtProofs = jwtProofs
  }
}

public struct BackgroundImage: Codable, Equatable {
  public let url: URL
  
  public init(uri: String) throws {
    guard let url = URL(string: uri) else {
      throw BackgroundImageError.invalidURL
    }
    self.url = url
  }
  
  public init(json: JSON) throws {
    let uri = json["uri"].stringValue
    try self.init(uri: uri)
  }
  
  enum CodingKeys: String, CodingKey {
    case uri
  }
  
  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let uri = try container.decode(String.self, forKey: .uri)
    try self.init(uri: uri)
  }
  
  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(url.absoluteString, forKey: .uri)
  }
}

public enum BackgroundImageError: Error {
  case invalidURL
}
