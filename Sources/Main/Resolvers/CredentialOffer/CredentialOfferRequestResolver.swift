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

public protocol CredentialOfferRequestResolverType {
  /// The input type for resolving a type.
  associatedtype InputType

  /// The output type for resolved type. Must be Codable and Equatable.
  associatedtype OutputType: Codable, Equatable
  
  /// The fetch type for resolved type. Must be Codable and Equatable.
  associatedtype FetchType: Codable, Equatable

  /// The error type for resolving type. Must conform to the Error protocol.
  associatedtype ErrorType: Error

  /// Resolves type asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching data.
  ///   - source: The input source for resolving data.
  /// - Returns: An asynchronous result containing the resolved data or an error.
  func resolve(
    fetcher: Fetcher<FetchType>,
    source: InputType?
  ) async -> Result<OutputType?, ErrorType>
}

public actor CredentialOfferRequestResolver {
  
  private let fetcher: Fetcher<CredentialOfferRequestObject>
  private let credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver
  private let authorizationServerMetadataResolver: AuthorizationServerMetadataResolver
  
  /// Initializes an instance of YourClass.
  ///
  /// - Parameters:
  ///   - credentialIssuerMetadataResolver: An object responsible for resolving credential issuer metadata.
  ///   - authorizationServerMetadataResolver: An object responsible for resolving authorization server metadata.
  public init(
    fetcher: Fetcher<CredentialOfferRequestObject> = Fetcher(),
    credentialIssuerMetadataResolver: CredentialIssuerMetadataResolver,
    authorizationServerMetadataResolver: AuthorizationServerMetadataResolver
  ) {
    self.fetcher = fetcher
    self.credentialIssuerMetadataResolver = credentialIssuerMetadataResolver
    self.authorizationServerMetadataResolver = authorizationServerMetadataResolver
  }
  
  /// Resolves client metadata asynchronously.
  ///
  /// - Parameters:
  ///   - fetcher: The fetcher object responsible for fetching metadata. Default value is Fetcher<ClientMetaData>().
  ///   - source: The input source for resolving metadata.
  /// - Returns: An asynchronous result containing the resolved metadata or an error of type ResolvingError.
  public func resolve(
    source: CredentialOfferRequest?
  ) async -> Result<CredentialOffer?, Error> {
    guard let source = source else { return .success(nil) }
    do {
      switch source {
      case .passByValue(let value):
        guard
          let credentialOfferRequestObject: CredentialOfferRequestObject = .init(jsonString: value)
        else {
          return .failure(ValidationError.error(reason: "Unable to parse credential offer request"))
        }
        
        let credentialIssuerId = try CredentialIssuerId(string: credentialOfferRequestObject.credentialIssuer)
        guard let credentialIssuerMetadata = try? await credentialIssuerMetadataResolver.resolve(source: .credentialIssuer(credentialIssuerId)).get() else {
          return .failure(ValidationError.error(reason: "Invalid credential metadata"))
        }
        
        guard let authorizationServerMetadata = try? await authorizationServerMetadataResolver.resolve(url: credentialIssuerMetadata.authorizationServer).get() else {
          return .failure(ValidationError.error(reason: "Invalid authorization metadata"))
        }
        
        let domain = try toDomain(
          credentialOfferRequestObject: credentialOfferRequestObject,
          credentialIssuerMetadata: credentialIssuerMetadata,
          authorizationServerMetadata: authorizationServerMetadata
        )
        return .success(domain)
        
      case .fetchByReference(let url):
        let result = await fetcher.fetch(url: url)
        let credentialOfferRequestObject = try? result.get()
        if let credentialOfferRequestObject = credentialOfferRequestObject {
          let credentialIssuerId = try CredentialIssuerId(string: credentialOfferRequestObject.credentialIssuer)
          guard let credentialIssuerMetadata = try? await credentialIssuerMetadataResolver.resolve(source: .credentialIssuer(credentialIssuerId)).get() else {
            return .failure(ValidationError.error(reason: "Invalid credential metadata"))
          }
          
          guard let authorizationServerMetadata = try? await authorizationServerMetadataResolver.resolve(url: credentialIssuerMetadata.authorizationServer).get() else {
            return .failure(ValidationError.error(reason: "Invalid authorization metadata"))
          }
          
          let domain = try toDomain(
            credentialOfferRequestObject: credentialOfferRequestObject,
            credentialIssuerMetadata: credentialIssuerMetadata,
            authorizationServerMetadata: authorizationServerMetadata
          )
          return .success(domain)
        }
        return .failure(ValidationError.error(reason: "Unable to fetch credential offer request by reference"))
      }
    } catch {
      return .failure(ValidationError.error(reason: error.localizedDescription))
    }
  }
  
  func toDomain(
    credentialOfferRequestObject: CredentialOfferRequestObject,
    credentialIssuerMetadata: CredentialIssuerMetadata?,
    authorizationServerMetadata: CIAuthorizationServerMetadata
  ) throws -> CredentialOffer {
    
    guard let credentialIssuerMetadata = credentialIssuerMetadata else {
      throw ValidationError.error(reason: "Invalid to fetch credential offer request by reference")
    }
    
    do {
      let credentialIssuerId = credentialIssuerMetadata.credentialIssuerIdentifier
      let credentials: [CredentialMetadata] = try self.computeCredentialMetadata(credentialOfferRequestObject: credentialOfferRequestObject)
      let grants = try credentialOfferRequestObject.grants?.toDomain()
      return try .init(
        credentialIssuerIdentifier: credentialIssuerId,
        credentialIssuerMetadata: credentialIssuerMetadata,
        credentials: credentials,
        grants: grants,
        authorizationServerMetadata: authorizationServerMetadata
      )
    } catch {
      throw ValidationError.error(reason: error.localizedDescription)
    }
  }
  
  private func computeCredentialMetadata(
    credentialOfferRequestObject: CredentialOfferRequestObject
  ) throws -> [CredentialMetadata] {
    try credentialOfferRequestObject.credentials.map { element in
      if element.type == .string,
         let string = element.string {
        return .byScope(try .init(value: string))
        
      } else if element.type == .dictionary,
             let dictionary = element.dictionary {
        if dictionary["format"]?.type == .string,
           let format = dictionary["format"]?.string {
          switch format {
          case MsoMdocProfile.FORMAT:
            return .byProfile
          case SdJwtVcProfile.FORMAT:
            return .byProfile
          default:
            return .byProfile
          }
          
        } else {
          throw ValidationError.error(reason: "Invalid 'format'")
        }
      } else {
        throw ValidationError.error(reason: "Invalid JsonElement for Credential. Found \(element.type)")
      }
    }
  }
}