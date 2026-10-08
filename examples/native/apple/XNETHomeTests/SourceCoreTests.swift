import XCTest
@testable import XNETSourceCore

final class SourceCoreTests: XCTestCase {
    private func root() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("xnet-home-test-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func fixture(_ text: String = "Cafe owner: Morgan. The invoice totals nine dollars.") throws
        -> (LocalSourceVault, LocalSourceRecord, [LocalSourceCard]) {
        var vault = try LocalSourceVault(root: root())
        let source = try vault.admit(bytes: Data(text.utf8), title: "Fixture")
        let cards = try SourceRetrieval.cards(from: vault.original(id: source.id))
        return (vault, source, cards)
    }

    private func response(_ citations: [LiteralCitation], answer: String = "Nine dollars.") throws -> String {
        String(decoding: try JSONEncoder().encode(AnswerEnvelope(answer: answer,
            citations: citations)), as: UTF8.self)
    }

    func testOriginalRoundTripPreservesUTF8AndNewlines() throws {
        let text = "hello\r\n世界 😀\n"
        let (vault, source, _) = try fixture(text)
        let reopened = try LocalSourceVault(root: vault.root)
        XCTAssertEqual(try reopened.original(id: source.id).bytes, Data(text.utf8))
        XCTAssertEqual(source.sha256, LocalHashes.sha256(Data(text.utf8)))
        XCTAssertEqual(source.classification, "private")
    }

    func testMalformedUTF8RefusedWithoutManifest() throws {
        var vault = try LocalSourceVault(root: root())
        XCTAssertThrowsError(try vault.admit(bytes: Data([0xc3, 0x28]), title: "bad"))
        XCTAssertTrue(vault.records.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: vault.root.appendingPathComponent("manifest.json").path))
    }

    func testOriginalTamperDoesNotUpdateManifestPin() throws {
        let (vault, source, _) = try fixture()
        let original = vault.root.appendingPathComponent("originals")
            .appendingPathComponent(source.id + ".utf8")
        try Data("tampered".utf8).write(to: original)
        let reopened = try LocalSourceVault(root: vault.root)
        XCTAssertEqual(reopened.records.first?.sha256, source.sha256)
        XCTAssertThrowsError(try reopened.original(id: source.id))
    }

    func testInvalidManifestIsPreservedAndRefused() throws {
        let directory = try root()
        let url = directory.appendingPathComponent("manifest.json")
        let forged = Data("{\"version\":1,\"sources\":[{\"id\":\"../outside\"}]}".utf8)
        try forged.write(to: url)
        XCTAssertThrowsError(try LocalSourceVault(root: directory))
        XCTAssertEqual(try Data(contentsOf: url), forged)
    }

    func testSourceAndArchiveLimits() throws {
        var vault = try LocalSourceVault(root: root())
        XCTAssertThrowsError(try vault.admit(
            bytes: Data(repeating: 65, count: LocalSourceVault.maximumSourceBytes + 1), title: "large"))
        for index in 0..<32 {
            _ = try vault.admit(bytes: Data("a".utf8), title: "\(index)")
        }
        XCTAssertThrowsError(try vault.admit(bytes: Data("a".utf8), title: "33"))
    }

    func testSourceClassificationIsKeptInCards() throws {
        var vault = try LocalSourceVault(root: root())
        let record = try vault.admit(bytes: Data("private detail".utf8), title: "detail",
            classification: "restricted")
        let cards = try SourceRetrieval.cards(from: vault.original(id: record.id))
        XCTAssertEqual(cards.first?.classification, "restricted")
        XCTAssertThrowsError(try vault.admit(bytes: Data("x".utf8), title: "x",
            classification: "automatically-public"))
    }

    func testUTF8SlicesReconstructEveryByte() throws {
        let text = String(repeating: "abc世界😀\n", count: 20)
        let (vault, record, _) = try fixture(text)
        let original = try vault.original(id: record.id)
        let cards = try SourceRetrieval.cards(from: original, maximumBytes: 16)
        XCTAssertGreaterThan(cards.count, 1)
        XCTAssertEqual(cards.reduce(into: Data()) { $0.append(Data($1.utf8.utf8)) }, original.bytes)
        for card in cards {
            XCTAssertLessThanOrEqual(card.utf8.utf8.count, 16)
            XCTAssertEqual(card.utf8.utf8.count, card.endByte - card.startByte)
            XCTAssertNoThrow(try SourceRetrieval.verify(card, against: original))
        }
    }

    func testAlteredCardTextOrClassificationRefused() throws {
        let (vault, record, cards) = try fixture()
        let c = try XCTUnwrap(cards.first)
        let altered = LocalSourceCard(id: c.id, originalID: c.originalID,
            originalSHA256: c.originalSHA256, startByte: c.startByte, endByte: c.endByte,
            utf8: c.utf8 + "forged", sha256: c.sha256, classification: c.classification)
        XCTAssertThrowsError(try SourceRetrieval.verify(altered, against: vault.original(id: record.id)))
        let relabeled = LocalSourceCard(id: c.id, originalID: c.originalID,
            originalSHA256: c.originalSHA256, startByte: c.startByte, endByte: c.endByte,
            utf8: c.utf8, sha256: c.sha256, classification: "public")
        XCTAssertThrowsError(try SourceRetrieval.verify(relabeled, against: vault.original(id: record.id)))
    }

    func testChangedOriginalCannotValidateAnOldCard() throws {
        let (_, record, cards) = try fixture()
        let c = try XCTUnwrap(cards.first)
        let forgedOriginal = VerifiedLocalOriginal(record: record, bytes: Data(c.utf8.uppercased().utf8))
        XCTAssertThrowsError(try SourceRetrieval.verify(c, against: forgedOriginal))
    }

    func testLexicalRankingIsDeterministicAndCaseFolded() throws {
        // Split small enough that the query-relevant text and unrelated prefix differ.
        let (vault, record, _) = try fixture("nothing here abc! Café BILL total nine.")
        let slices = try SourceRetrieval.cards(from: vault.original(id: record.id), maximumBytes: 16)
        let ranked = SourceRetrieval.rank(slices, query: "CAFE bill")
        XCTAssertEqual(ranked, SourceRetrieval.rank(Array(slices.reversed()), query: "CAFE bill"))
        XCTAssertTrue(try XCTUnwrap(ranked.first).utf8.contains("Café"))
        XCTAssertEqual(SourceRetrieval.rank(slices, query: ""), slices)
    }

    func testLiteralQuoteAcceptedWithoutCorrectnessClaim() throws {
        let (_, _, cards) = try fixture()
        let card = try XCTUnwrap(cards.first)
        let cite = LiteralCitation(sourceID: card.id, sha256: card.sha256, quote: "nine dollars")
        let result = LiteralEvidence.check(rawReply: try response([cite]), cards: cards)
        XCTAssertEqual(result.matchingQuotes, 1)
        XCTAssertEqual(result.matchedCitationIndexes, [0])
        XCTAssertFalse(result.answerCorrectnessVerified)
        XCTAssertFalse(result.meaningOrCompletenessVerified)
    }

    func testForgedIDHashAndQuoteRejected() throws {
        let (_, _, cards) = try fixture()
        let card = try XCTUnwrap(cards.first)
        let citations = [
            LiteralCitation(sourceID: "missing", sha256: card.sha256, quote: "nine dollars"),
            LiteralCitation(sourceID: card.id, sha256: String(repeating: "0", count: 64), quote: "nine dollars"),
            LiteralCitation(sourceID: card.id, sha256: card.sha256, quote: "nine thousand dollars")
        ]
        let result = LiteralEvidence.check(rawReply: try response(citations), cards: cards)
        XCTAssertEqual(result.matchingQuotes, 0)
        XCTAssertEqual(result.rejectedQuotes, 3)
    }

    func testDuplicateQuoteCountsOnce() throws {
        let (_, _, cards) = try fixture()
        let card = try XCTUnwrap(cards.first)
        let cite = LiteralCitation(sourceID: card.id, sha256: card.sha256, quote: "nine dollars")
        let result = LiteralEvidence.check(rawReply: try response([cite, cite]), cards: cards)
        XCTAssertEqual(result.matchingQuotes, 1)
        XCTAssertEqual(result.rejectedQuotes, 1)
        XCTAssertEqual(result.matchedCitationIndexes, [0])
    }

    func testCanonicallyEquivalentUnicodeIsNotByteEvidence() throws {
        let (_, _, cards) = try fixture("Café")
        let card = try XCTUnwrap(cards.first)
        let cite = LiteralCitation(sourceID: card.id, sha256: card.sha256, quote: "Cafe\u{301}")
        XCTAssertEqual(LiteralEvidence.check(rawReply: try response([cite]), cards: cards).matchingQuotes, 0)
    }

    func testMalformedReplyRemainsWholeAndUngraded() throws {
        let (_, _, cards) = try fixture()
        let raw = "{\"answer\":\"incomplete"
        let result = LiteralEvidence.check(rawReply: raw, cards: cards)
        XCTAssertEqual(result.answer, raw)
        XCTAssertFalse(result.envelopeParsed)
        XCTAssertFalse(result.answerCorrectnessVerified)
    }

    func testEmptyCitationNeverCountsAsSupport() throws {
        let (_, _, cards) = try fixture()
        let card = try XCTUnwrap(cards.first)
        let result = LiteralEvidence.check(rawReply: try response([
            LiteralCitation(sourceID: card.id, sha256: card.sha256, quote: "")]), cards: cards)
        XCTAssertEqual(result.matchingQuotes, 0)
        XCTAssertEqual(result.rejectedQuotes, 1)
    }

    func testAnswerReceiptReadBackHashAndNoOverwrite() throws {
        let (vault, _, _) = try fixture()
        let id = UUID()
        let receipt = ["raw_completed_reply": "full original output", "answer_correctness": "ungraded"]
        let digest = try vault.saveAnswer(receipt, id: id)
        let bytes = try Data(contentsOf: vault.root.appendingPathComponent("answers")
            .appendingPathComponent(id.uuidString.lowercased() + ".json"))
        XCTAssertEqual(digest, LocalHashes.sha256(bytes))
        XCTAssertThrowsError(try vault.saveAnswer(receipt, id: id))
    }
}
