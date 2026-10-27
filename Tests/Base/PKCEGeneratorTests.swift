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
import XCTest
import CryptoKit
@testable import OpenID4VCI

class PKCEGeneratorTests: XCTestCase {
  
  func testGenerateRandomData() {
    let length = 48
    if let randomData = PKCEGenerator.generateRandomData(length: length) {
      XCTAssertEqual(randomData.count, length)
    } else {
      XCTFail("Failed to generate random data")
    }
  }
  
  func testGenerateRandomBase64String() {
    let length = 48
    guard let randomString = PKCEGenerator.generateRandomBase64String(length: length) else {
      XCTFail("Failed to generate random base64 string")
      return
    }
    
    XCTAssert(true, "Generated random base64 string \(randomString)")
  }
  
  func testGenerateRandomBase64StringOfLength43() {
    let length = 32
    guard let randomString = PKCEGenerator.generateRandomBase64String(length: length) else {
      XCTFail("Failed to generate random base64 string")
      return
    }
    
    XCTAssert(true, "Generated random base64 string \(randomString)")
  }
  
  func testGenerateCodeChallenge() {
    if let codeChallenge = PKCEGenerator.generateCodeChallenge() {
      XCTAssertEqual(codeChallenge.count, 44) // Base64-encoded SHA256 hash length
    } else {
      XCTFail("Failed to generate code challenge")
    }
  }

  // MARK: - Uniform distribution (CWE-340)

  func testCodeVerifierHasRequestedLengthAndUsesUnreservedCharacters() throws {
    let alphabet = Set(PKCEGenerator.unreservedCharacters)
    XCTAssertEqual(alphabet.count, 66)

    for length in [43, 64, 128] {
      let verifier = try XCTUnwrap(PKCEGenerator.codeVerifier(length: length))
      XCTAssertEqual(verifier.count, length)
      XCTAssertTrue(verifier.allSatisfy(alphabet.contains), "Unexpected character in \(verifier)")
    }
    XCTAssertNil(PKCEGenerator.codeVerifier(length: 42))
    XCTAssertNil(PKCEGenerator.codeVerifier(length: 129))
  }

  func testGenerateRandomBase64StringEncodesUnreservedCharacters() throws {
    let alphabet = Set(PKCEGenerator.unreservedCharacters)
    let encoded = try XCTUnwrap(PKCEGenerator.generateRandomBase64String(length: 48))
    let decoded = try XCTUnwrap(Data(base64Encoded: encoded).flatMap { String(data: $0, encoding: .utf8) })
    XCTAssertEqual(decoded.count, 48)
    XCTAssertTrue(decoded.allSatisfy(alphabet.contains))
  }

  /// With `byte % 66`, indexes 0...57 occur with probability 4/256 and 58...65 with 3/256.
  /// Over 132,000 samples (2,000 expected per character) that bias yields chi-square ≈ 934,
  /// while a uniform generator yields ≈ 65 ± 11 (65 degrees of freedom). A threshold of 150
  /// separates the two with a negligible false-failure rate.
  func testGenerateRandomStringIsUniformlyDistributed() throws {
    let alphabet = PKCEGenerator.unreservedCharacters
    let expectedPerCharacter = 2_000
    let sampleSize = alphabet.count * expectedPerCharacter

    let sample = try XCTUnwrap(PKCEGenerator.generateRandomString(length: sampleSize))
    XCTAssertEqual(sample.count, sampleSize)

    var counts: [Character: Int] = [:]
    for character in sample {
      counts[character, default: 0] += 1
    }
    XCTAssertEqual(Set(counts.keys), Set(alphabet), "Every character must appear")

    let expected = Double(expectedPerCharacter)
    let chiSquare = alphabet.reduce(0.0) { sum, character in
      let observed = Double(counts[character, default: 0])
      return sum + (observed - expected) * (observed - expected) / expected
    }
    XCTAssertLessThan(chiSquare, 150, "Character distribution is not uniform (chi-square \(chiSquare))")
  }

  func testUniformRandomStringSupportsAlphabetThatDividesByteRange() throws {
    // 64 divides 256, so no byte is rejected; exercises the limit calculation edge.
    let alphabet = Array(PKCEGenerator.unreservedCharacters.prefix(64))
    let value = try XCTUnwrap(PKCEGenerator.uniformRandomString(length: 100, alphabet: alphabet))
    XCTAssertEqual(value.count, 100)
    XCTAssertTrue(value.allSatisfy(Set(alphabet).contains))
  }
}
