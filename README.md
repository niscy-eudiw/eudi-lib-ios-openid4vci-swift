# EUDI OpenId4VCI library

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Table of contents

* [Overview](#overview)
* [Disclaimer](#disclaimer)
* [How to use](#how-to-use)
* [Configuration options](#configuration-options)  
* [Features supported](#features-supported)
* [Features not supported](#features-not-supported)
* [How to contribute](#how-to-contribute)
* [License](#license)


## Overview

This is a Swift library, that supports 
the  [OpenId4VCI (draft 15)](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html) protocol.

In particular, the library focuses on the wallet's role in the protocol to:
- Resolve credential issuer metadata 
- Resolve metadata of the authorization server protecting issuance services
- Resolve a credential offer presented by an issuer service
- Negotiate authorization of a credential issuance request
- Submit a credential issuance request


| Feature                                                                                         | Coverage                                                                                                           |
|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| Credential Issusance                                         | ✅                                                                                                                  |
| Resolve a credential offer                                      | ✅ Unsigned metadata ✅ signed metadata ❌ [accept-language](#issuer-metadata-accept-language)                        |
| Authorization code flow                                            | ✅                                                                                                                  |
| Pre-authorized code flow                                        | ✅                                                                                                                  |
| mso_mdoc format                                                                                 | ✅                                                                                                                  |
| SD-JWT-VC format                                                                                | ✅                                                                                                                  |
| W3C Formats                                                                                   | ❌                                                                              |
| Place credential request                                         | ✅                                               |
| Query for deferred credentials                             | ✅                                                                   |
| Notify credential issuer                                     | ✅                                                                                                                  | 
| Proof                                                                                           | ✅ JWT                                                                                                              |
| Credential response encryption                                                                  | ✅                                                                                                                  |
| Pushed authorization requests                                | ✅ Used by default, if supported by issuer                                                                          |
| Demonstrating Proof of Possession (DPoP)           | ✅                                                                                                                  |
| PKCE                             | ✅                                                                                                                  |
| Wallet authentication                                                                           | ✅ public client, <br/>✅ [Attestation-Based Client Authentication](#oauth2-attestation-based-client-authentication) |
| Use issuer's nonce endpoint to get c_nonce for proofs                                           | ✅                                                                                                                  |
| `attestation` proof type                                                                        | ❌                                                                                                                  |
| `key_attestation` to the JWT Proof (JOSE header)                                                | ❌                                                                                                                  |
| Wallet attestation                                                                              | ❌                                                                                                                  |


## Disclaimer

The released software is an initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported

## How to use

The library provides the following main api elements to facilitate consumers of this api with the operations related to verifiable credentials issuance  

- **Metadata resolvers**: Components that interact with a credential issuer and its authorization server to obtain and parse their metadata.  
- **Credential offer resolver**: A component that interacts with credential issuer to resolve and validate a credential offer presented by the issuer.  
- **Issuer component**: A component that offers all operation required to authorize and submit a credential issuance request.

### Resolve Credential Issuer and authorization server metadata

To obtain the credentials issuer metadata use the ```CredentialIssuerMetadataResolver``` actor the following way:

```swift
import OpenID4VCI

let credentialIdentifier = try CredentialIdentifier(value: "https://....")
let credentialIssuerIdentifier = try CredentialIssuerId(CREDENTIAL_ISSUER_PUBLIC_URL)
    
let resolver = CredentialIssuerMetadataResolver()
let metadata = await resolver.resolve(
    source: .credentialIssuer(
        credentialIssuerIdentifier
    )
)

switch metadata {
    ...
}
```
In case of failure the reason will be returned in an Error.



To obtain the authorization server's metadata use the ```AuthorizationServerMetadataResolver``` the following way:

```swift
import OpenID4VCI

let resolver = AuthorizationServerMetadataResolver()
let authServerMetadata = await resolver.resolve(url: "https://....")
```

The url can be obtained from the credential issuer metadata above.

### Resolve a credential offer

A ```CredentialOfferRequestResolver``` uses the two metadata resolvers mentioned above internally, to resolve metadata of an issuer and its authorization server

Given a credential offer url use the ```CredentialOfferRequestResolver``` the following way to validate and resolve it to a ```CredentialOffer```

```swift
import OpenID4VCI

let resolver = CredentialOfferRequestResolver()
let result = await resolver
  .resolve(
    source: try .init(
      urlString: url
    )
  )
    
switch result {
    ...
}
```

### Credential Issuance

The OpenID4VCI specification defines two flows of issuance:
- Authorization Code Flow (wallet-initiated flow)
- Pre-Authorization Code Flow. In this flow, before initiating the flow with the Wallet, the Credential Issuer first conducts the steps required to prepare the Credential issuance.

### Issuer

The ```Issuer``` is the component that facilitates the authorization and submission of a credential issuance request.
It consists of two components:
- **IssuanceAuthorizer**: A component responsible for all interactions with an authorization server to authorize a request for credential issuance.
- **IssuanceRequester**: A component responsible for all interactions with a credential issuer for submitting credential issuance requests.

#### Initialize an Issuer

```swift
import OpenID4VCI

let credentialIdentifier = try CredentialIdentifier(value: "https://....")
let credentialIssuerIdentifier = try CredentialIssuerId(CREDENTIAL_ISSUER_PUBLIC_URL)
let offer: CredentialOffer = ...
let config: OpenId4VCIConfig = ...

let issuer = try Issuer(
    authorizationServerMetadata: offer.authorizationServerMetadata,
    issuerMetadata: offer.credentialIssuerMetadata,
    config: config
)
```

#### Authorize request via Authorization Code Flow

Given an ```Issuer``` use [Authorization Code Flow](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-3.4) to authorize an issuance request.     

```swift
import OpenID4VCI

let parPlaced = await issuer.pushAuthorizationCodeRequest(
  credentialOffer: offer
)

if case let .success(request) = parPlaced,
   case let .par(parRequested) = request {
      
    let authorizationCode = ...
    let issuanceAuthorization: IssuanceAuthorization = .authorizationCode(authorizationCode: authorizationCode)
    let unAuthorized = await issuer.handleAuthorizationCode(
        parRequested: request,
        authorizationCode: issuanceAuthorization
      )
      
    switch unAuthorized {
      case .success(let request):
        let authorizedRequest = await issuer.requestAccessToken(authorizationCode: request)
        
        if case let .success(authorized) = authorizedRequest,
           case let .noProofRequired(token) = authorized {
          print("\(token.accessToken)")
        }
        
      case .failure:
        throw ...
      }
    }
    throw ...
}
```

#### Authorize request via Pre-Authorization Code Flow

Given an ```Issuer``` use [Pre-Authorization Code Flow](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-3.5) to authorize an issuance request.

```swift
import OpenID4VCI

let issuer: Issuer = ...
let preAuthorizationCode = ... // pre-authorization code as contained in a credential offer 
let authorizedRequest = await issuer.authorizeWithPreAuthorizationCode(
    credentialOffer: ...,
    authorizationCode: ...,
    clientId: ...,
    transactionCode: ...
  )
```

#### Request a single credential issuance

Given an ```authorizedRequest``` and an ```Issuer``` a single credential issuance request can be placed as follows

```swift
import OpenID4VCI

let payload: IssuanceRequestPayload = .configurationBased(
  credentialConfigurationIdentifier: ...
)

let requestOutcome = try await issuer.requestCredential(
    proofRequest: ...,
    bindingKeys: ..., // SigningKeyProxy array
    requestPayload: payload,
    responseEncryptionSpecProvider:  { 
        Issuer.createResponseEncryptionSpec($0) 
    }
)

switch requestOutcome {
    case .success(let request):
      switch request {
      case .success(let response):
        ...
      case .invalidProof:
        ...
      case .failed(let error):
        ...
      }
    case .failure(let error): 
      ...
    }
}
```

You can also check the unit test target for more usage examples.

## Configuration options

```swift
public struct OpenId4VCIConfig: Sendable {
  public let client: Client
  public let authFlowRedirectionURI: URL
  public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
  public let usePAR: Bool
  public let dPoPConstructor: DPoPConstructorType?
  public let clientAttestationPoPBuilder: ClientAttestationPoPBuilder?
  public let issuerMetadataPolicy: IssuerMetadataPolicy
}
```

- `client`: Wallet client authentication method in the OAUTH2 sense while interacting with the Credential Issuer
  - Either Public Client (`public`)
  - Attestation-Based Client Authentication (`attested`)

- `authFlowRedirectionURI`: It is the `redirect_uri` parameter that will be included in a PAR or simple authorization request.
- `authorizeIssuanceConfig`: An enum that allows you to favour scopes or authorization details, favour scopes is the default.
- `usePAR`: Force the usage of PAR if the authorization server supports it.
- `dPoPConstructor`: If dpop is supported this option constructs what is required.
- `clientAttestationPoPBuilder`: If the authorization supports client attestations, this object constructs what is required.
- `issuerMetadataPolicy`: Trust between the Wallet and the Signer of the signed metadata advertised by the Credential Issuer is established using this configuration option.

## Features supported

### Authorization Endpoint
Specification defines ([section 5.1.1](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-5.1.1)) that a credential's issuance can be requested using authorization_details parameter when using authorization code flow.
Current version of the library does not support that. It only supports requesting issuance using `scope` parameter in the authorization endpoint. 

### Token Endpoint
Specification defines ([section 6.2](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-6.2)) that upon a successful token response `authorization_details` is included in response,
if `authorization_details` parameter is used in authorization endpoint. Current version of library is not parsing/utilizing this response attribute.

### Credential Request
Current version of the library implements integrations with issuer's [Crednetial Endpoint](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-credential-endpoint) and
[Deferred Crednetial Endpoint](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#name-deferred-credential-endpoin)
endpoints.

**NOTE:** Attribute `credential_identifier` of a credential request is not yet supported.

#### Credential Format Profiles
OpenId4VCI specification defines several extension points to accommodate the differences across Credential formats. The current version of the library fully supports **ISO mDL** profile and gives some initial support for **IETF SD-JWT VC** profile.  

#### Proof Types
OpenId4VCI specification (draft 14) defines proofs that can be included in a credential issuance request, JWT proof type in particular. The current version of the library supports JWT proof types.

### Demonstrating Proof of Possession (DPoP)

The library supports [RFC9449](https://datatracker.ietf.org/doc/html/rfc9449). In addition to the 
bearer authentication scheme, the library can be configured to use DPoP authentication provided
that the authorization server, that protects the credential issuer, supports this feature as well.

If wallet [configuration](#configuration-options) provides a DPoP Signer and if the credential issuer advertises DPoP with
algorithms supported by wallet's DPoP Signer, then library will transparently request
for a DPoP `access_token` instead of the default Bearer token.

Furthermore, all further interactions will use the correct token type (Bearer or DPoP)

Library supports both
[Authorization Server-Provided Nonce](https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid) and
[Resource Server-Provided Nonce](https://datatracker.ietf.org/doc/html/rfc9449#name-resource-server-provided-no). It
features automatic recovery/retry support, and is able to recover from `use_dpop_nonce` errors given that a new DPoP
Nonce is provided in the `DPoP-Nonce` header. Finally, library refreshes DPoP Nonce whenever a new value is provided,
either by the Authorization Server or the Credential Issuer, using the `DPoP-Nonce` header, and all subsequent
interactions use the newly provided DPoP Nonce value.

### OAUTH2 Attestation-Based Client Authentication

Library supports [OAUTH2 Attestation-Based Client Authentication - Draft 03](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-03.html)

An example can be found in this test: `testNoOfferSdJWTClientAuthentication()`

#### Notes

Examples for all of the above are located in the test target of the library.

## Features not supported

### Issuer metadata accept-language

[Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html#name-credential-issuer-metadata-) recommends the use of header `Accept-Language` to indicate the language(s) preferred for display.
Current version of the library does not support this.

### Authorization

[Specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-14.html#name-using-authorization-details) defines that a credential's issuance
can be requested using `authorization_details` or `scope` parameter when using authorization code flow. The current version of the library supports usage of both parameters.
Though for `authorization_details` we don't support the `format` attribute and its specializations per format.
Only `credential_configuration_id` attribute is supported.

### Key attestations

Current version of the library does not support [key attestations](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#appendix-D) 
neither as a [proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-8.2.1.3) nor as a `key_attestation` header in JWT proofs.

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### Third-party component licenses

* JOSE Support: [JOSESwift](https://github.com/airsidemobile/JOSESwift)
* JSON Support: [SwiftyJSON](https://github.com/SwiftyJSON/SwiftyJSON)

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
