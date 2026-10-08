import Foundation

struct LiteralCitation: Codable, Equatable, Sendable {
    let sourceID: String
    let sha256: String
    let quote: String

    enum CodingKeys: String, CodingKey {
        case sourceID = "source_id"
        case sha256, quote
    }
}

struct AnswerEnvelope: Codable, Sendable {
    let answer: String
    let citations: [LiteralCitation]
}

struct LiteralEvidenceResult: Codable, Sendable {
    let envelopeParsed: Bool
    let answer: String
    let citations: [LiteralCitation]
    let matchingQuotes: Int
    let rejectedQuotes: Int
    let matchedCitationIndexes: [Int]
    let answerCorrectnessVerified: Bool
    let meaningOrCompletenessVerified: Bool
}

enum LiteralEvidence {
    static func check(rawReply: String, cards: [LocalSourceCard]) -> LiteralEvidenceResult {
        guard let bytes = rawReply.data(using: .utf8), bytes.count <= 262_144,
              let envelope = try? JSONDecoder().decode(AnswerEnvelope.self, from: bytes),
              envelope.citations.count <= 32 else {
            return LiteralEvidenceResult(envelopeParsed: false, answer: rawReply, citations: [],
                matchingQuotes: 0, rejectedQuotes: 0, matchedCitationIndexes: [], answerCorrectnessVerified: false,
                meaningOrCompletenessVerified: false)
        }
        var seen: Set<LiteralCitationKey> = []
        var matchedIndexes: [Int] = []
        for (index, citation) in envelope.citations.enumerated() {
            let key = LiteralCitationKey(id: citation.sourceID, hash: citation.sha256, quote: citation.quote)
            if let card = cards.first(where: { $0.id == citation.sourceID }),
               card.sha256 == citation.sha256, !citation.quote.isEmpty,
               citation.quote.utf8.count <= 4096,
               Data(card.utf8.utf8).range(of: Data(citation.quote.utf8)) != nil,
               seen.insert(key).inserted {
                matchedIndexes.append(index)
            }
        }
        return LiteralEvidenceResult(envelopeParsed: true, answer: envelope.answer,
            citations: envelope.citations, matchingQuotes: matchedIndexes.count,
            rejectedQuotes: envelope.citations.count - matchedIndexes.count,
            matchedCitationIndexes: matchedIndexes,
            answerCorrectnessVerified: false, meaningOrCompletenessVerified: false)
    }

    private struct LiteralCitationKey: Hashable {
        let id: String
        let hash: String
        let quote: String
    }
}
