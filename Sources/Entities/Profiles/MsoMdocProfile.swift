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

public struct MsoMdocProfile: Profile {
  static let FORMAT = "mso_mdoc"
  
  public let docType: String
  public let scope: String?
  
  enum CodingKeys: String, CodingKey {
    case docType = "doctype"
    case scope
  }
  
  init(docType: String, scope: String?) {
    self.docType = docType
    self.scope = scope
  }
}

public extension MsoMdocProfile {
  
  struct CredentialSupportedDTO: Codable {
    public let format: String
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [String]?
    public let cryptographicSuitesSupported: [String]?
    public let proofTypesSupported: [String]?
    public let display: [Display]?
    public let docType: String
    public let claims: [String: [String: Claim]]?
    public let order: [String]?
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case cryptographicSuitesSupported = "cryptographic_suites_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case docType = "doctype"
      case claims
      case order
    }
    
    public init(
      format: String,
      scope: String? = nil,
      cryptographicBindingMethodsSupported: [String]? = nil,
      cryptographicSuitesSupported: [String]? = nil,
      proofTypesSupported: [String]? = nil,
      display: [Display]? = nil,
      docType: String,
      claims: [String : [String : Claim]]? = nil,
      order: [String]? = nil
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.cryptographicSuitesSupported = cryptographicSuitesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.docType = docType
      self.claims = claims
      self.order = order
    }
    
    func toDomain() throws -> MsoMdocProfile.CredentialSupported {
      
      let bindingMethods = try cryptographicBindingMethodsSupported?.compactMap {
        try CryptographicBindingMethod(method: $0)
      } ?? []
      let display: [Display] = self.display ?? []
      let proofTypesSupported: [ProofType] = try self.proofTypesSupported?.compactMap {
        try ProofType(type: $0)
      } ?? { throw ValidationError.error(reason: "No proof types found")}()
      let cryptographicSuitesSupported: [String] = self.cryptographicSuitesSupported ?? []
      let claims: MsoMdocClaims = claims?.mapValues { namespaceAndClaims in
        namespaceAndClaims.mapValues { claim in
          Claim(
            mandatory: claim.mandatory ?? false,
            valueType: claim.valueType,
            display: claim.display?.compactMap {
              Display(
                name: $0.name,
                locale: $0.locale
              )
            }
          )
        }
      } ?? [:]
      
      return .init(
        format: format,
        scope: scope,
        cryptographicBindingMethodsSupported: bindingMethods,
        cryptographicSuitesSupported: cryptographicSuitesSupported,
        proofTypesSupported: proofTypesSupported,
        display: display,
        docType: docType,
        claims: claims,
        order: order ?? []
      )
    }
  }
  
  struct CredentialSupported: Codable {
    public let format: String?
    public let scope: String?
    public let cryptographicBindingMethodsSupported: [CryptographicBindingMethod]
    public let cryptographicSuitesSupported: [String]
    public let proofTypesSupported: [ProofType]?
    public let display: [Display]
    public let docType: String
    public let claims: MsoMdocClaims
    public let order: [ClaimName]
    
    enum CodingKeys: String, CodingKey {
      case format
      case scope
      case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
      case cryptographicSuitesSupported = "cryptographic_suites_supported"
      case proofTypesSupported = "proof_types_supported"
      case display
      case docType = "doctype"
      case claims
      case order
    }
    
    public init(
      format: String?,
      scope: String?,
      cryptographicBindingMethodsSupported: [CryptographicBindingMethod],
      cryptographicSuitesSupported: [String],
      proofTypesSupported: [ProofType]?,
      display: [Display],
      docType: String,
      claims: MsoMdocClaims,
      order: [ClaimName]
    ) {
      self.format = format
      self.scope = scope
      self.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
      self.cryptographicSuitesSupported = cryptographicSuitesSupported
      self.proofTypesSupported = proofTypesSupported
      self.display = display
      self.docType = docType
      self.claims = claims
      self.order = order
    }
    
    public init(from decoder: Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      
      format = try container.decodeIfPresent(String.self, forKey: .format)
      scope = try container.decodeIfPresent(String.self, forKey: .scope)
      cryptographicBindingMethodsSupported = try container.decode([CryptographicBindingMethod].self, forKey: .cryptographicBindingMethodsSupported)
      cryptographicSuitesSupported = try container.decode([String].self, forKey: .cryptographicSuitesSupported)
      proofTypesSupported = try? container.decode([ProofType].self, forKey: .proofTypesSupported)
      display = try container.decode([Display].self, forKey: .display)
      docType = try container.decode(String.self, forKey: .docType)
      claims = try container.decode(MsoMdocClaims.self, forKey: .claims)
      order = try container.decode([ClaimName].self, forKey: .order)
    }
    
    public func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      
      try container.encode(format, forKey: .format)
      try container.encode(scope, forKey: .scope)
      try container.encode(cryptographicBindingMethodsSupported, forKey: .cryptographicBindingMethodsSupported)
      try container.encode(cryptographicSuitesSupported, forKey: .cryptographicSuitesSupported)
      try container.encode(proofTypesSupported, forKey: .proofTypesSupported)
      try container.encode(display, forKey: .display)
      try container.encode(docType, forKey: .docType)
      try container.encode(claims, forKey: .claims)
      try container.encode(order, forKey: .order)
    }
    
    init(json: JSON) throws {
      self.format = json["format"].string
      self.scope = json["scope"].string
      self.cryptographicBindingMethodsSupported = try json["cryptographic_binding_methods_supported"].arrayValue.map {
        try CryptographicBindingMethod(method: $0.stringValue)
      }
      self.cryptographicSuitesSupported = json["cryptographic_suites_supported"].arrayValue.map {
        $0.stringValue
      }
      self.proofTypesSupported = try json["proofTypesSupported"].arrayValue.map {
        try ProofType(type: $0.stringValue)
      }
      self.display = json["display"].arrayValue.map { json in
        Display(json: json)
      }
      self.docType = json["doctype"].stringValue
      self.claims = MsoMdocClaims(json: json["claims"])
      self.order = json["order"].arrayValue.map {
        ClaimName($0.stringValue)
      }
    }
  }
}

public extension MsoMdocProfile {
  
  static func matchSupportedAndToDomain(
    json: JSON,
    metadata: CredentialIssuerMetadata
  ) throws -> CredentialMetadata {
    guard let docType = json["doctype"].string else {
      throw ValidationError.error(reason: "Missing doctype")
    }
    
    if let credentialsSupported = metadata.credentialsSupported.first(where: { credential in
      switch credential {
      case .msoMdocProfile(let credentialSupported):
        return credentialSupported.docType == docType
      default: return false
      }
    }) {
      switch credentialsSupported {
      case .msoMdocProfile(let profile):
        return .msoMdoc(.init(docType: docType, scope: profile.scope))
      default: break
      }
    }
    
    throw ValidationError.error(reason: "Unable to parse a list of supported credentials")
  }
}
