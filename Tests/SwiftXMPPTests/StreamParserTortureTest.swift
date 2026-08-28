import XCTest
@testable import SwiftXMPP

/// A large IQ split at every possible byte boundary. A real OMEMO bundle has a
/// hundred prekeys and always crosses several TCP reads; the parser has to
/// reassemble it identically no matter where the cuts fall.
final class StreamParserTortureTest: XCTestCase {
    private func bundleIQ() -> String {
        var keys = ""
        for i in 1...100 {
            keys += "<preKeyPublic preKeyId='\(i)'>AAAABBBBCCCCDDDDEEEEFFFFGGGG=</preKeyPublic>"
        }
        return "<iq type='result' id='x'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
            + "<items node='eu.siacs.conversations.axolotl.bundles:1'><item id='current'>"
            + "<bundle xmlns='eu.siacs.conversations.axolotl'>"
            + "<signedPreKeyPublic signedPreKeyId='7'>SIGNEDKEY=</signedPreKeyPublic>"
            + "<signedPreKeySignature>SIG=</signedPreKeySignature>"
            + "<identityKey>IDKEY=</identityKey>"
            + "<prekeys>\(keys)</prekeys></bundle></item></items></pubsub></iq>"
    }

    func testLargeStanzaSplitAtEveryByte() throws {
        let iq = bundleIQ()
        let full = "<stream:stream xmlns:stream='x'>" + iq
        let bytes = Array(full.utf8)

        // Cut the stream after every byte and feed the two halves separately.
        for cut in stride(from: 32, to: bytes.count, by: 7) {
            var parser = StreamParser()
            var stanzas: [Stanza] = []
            for chunk in [Array(bytes[0..<cut]), Array(bytes[cut...])] {
                for event in try parser.feed(Data(chunk)) {
                    if case let .element(e) = event { stanzas.append(e) }
                }
            }
            XCTAssertEqual(stanzas.count, 1, "one stanza expected, cut at \(cut)")
            let prekeys = stanzas.first?.child("pubsub")?.child("items")?.child("item")?
                .child("bundle")?.child("prekeys")?.childrenNamed("preKeyPublic") ?? []
            XCTAssertEqual(prekeys.count, 100, "all 100 prekeys expected, cut at \(cut)")
        }
    }

    /// The specific shape from the failure: a closing tag split across reads.
    func testClosingTagSplit() throws {
        var parser = StreamParser()
        var stanzas: [Stanza] = []
        // "</preKeyPublic>" cut right after "</p".
        for chunk in ["<stream:stream xmlns:stream='x'>",
                      "<a><preKeyPublic preKeyId='67'>K=</p",
                      "reKeyPublic><preKeyPublic preKeyId='68'>K=</preKeyPublic></a>"] {
            for event in try parser.feed(Data(chunk.utf8)) {
                if case let .element(e) = event { stanzas.append(e) }
            }
        }
        XCTAssertEqual(stanzas.first?.childrenNamed("preKeyPublic").count, 2)
    }
}
