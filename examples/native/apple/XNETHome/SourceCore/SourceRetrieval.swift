import Foundation

struct LocalSourceCard: Codable, Identifiable, Equatable, Sendable {
    let id: String
    let originalID: String
    let originalSHA256: String
    let startByte: Int
    let endByte: Int
    let utf8: String
    let sha256: String
    let classification: String
}

enum SourceRetrieval {
    // Exact byte slices preserve the original. This is a transport budget, not tokens or HALO.
    static func cards(from original: VerifiedLocalOriginal, maximumBytes: Int = 1536) throws -> [LocalSourceCard] {
        guard maximumBytes >= 16, maximumBytes <= 8192,
              original.bytes.count == original.record.byteCount,
              LocalHashes.sha256(original.bytes) == original.record.sha256 else {
            throw LocalSourceError.changedSource
        }
        _ = try LocalHashes.strictUTF8(original.bytes)
        let bytes = [UInt8](original.bytes)
        var result: [LocalSourceCard] = []
        var start = 0
        while start < bytes.count {
            var end = min(start + maximumBytes, bytes.count)
            while end < bytes.count && (bytes[end] & 0xc0) == 0x80 { end -= 1 }
            guard end > start else { throw LocalSourceError.invalidText }
            let slice = Data(bytes[start..<end])
            let text = try LocalHashes.strictUTF8(slice)
            result.append(LocalSourceCard(
                id: original.record.id + ".c" + String(format: "%05d", result.count),
                originalID: original.record.id, originalSHA256: original.record.sha256,
                startByte: start, endByte: end, utf8: text,
                sha256: LocalHashes.sha256(slice), classification: original.record.classification))
            start = end
        }
        return result
    }

    static func rank(_ cards: [LocalSourceCard], query: String) -> [LocalSourceCard] {
        let wanted = terms(query)
        return cards.sorted { left, right in
            let leftScore = wanted.intersection(terms(left.utf8)).count
            let rightScore = wanted.intersection(terms(right.utf8)).count
            if leftScore != rightScore { return leftScore > rightScore }
            if left.originalID != right.originalID { return left.originalID < right.originalID }
            return left.startByte < right.startByte
        }
    }

    static func verify(_ card: LocalSourceCard, against original: VerifiedLocalOriginal) throws {
        guard original.bytes.count == original.record.byteCount,
              LocalHashes.sha256(original.bytes) == original.record.sha256,
              card.originalID == original.record.id,
              card.originalSHA256 == original.record.sha256,
              card.classification == original.record.classification,
              card.startByte >= 0, card.endByte > card.startByte,
              card.endByte <= original.bytes.count else { throw LocalSourceError.changedSource }
        let expected = original.bytes.subdata(in: card.startByte..<card.endByte)
        guard Data(card.utf8.utf8) == expected,
              LocalHashes.sha256(expected) == card.sha256 else { throw LocalSourceError.changedSource }
    }

    private static func terms(_ text: String) -> Set<String> {
        Set(text.folding(options: [.caseInsensitive, .diacriticInsensitive],
                locale: Locale(identifier: "en_US_POSIX"))
            .components(separatedBy: CharacterSet.alphanumerics.inverted)
            .filter { !$0.isEmpty })
    }
}
