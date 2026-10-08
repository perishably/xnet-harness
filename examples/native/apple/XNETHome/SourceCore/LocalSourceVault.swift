import Foundation
import CryptoKit

enum LocalSourceError: Error, LocalizedError {
    case invalidText, invalidManifest, changedSource, archiveLimit, invalidSelection

    var errorDescription: String? {
        switch self {
        case .invalidText: return "Choose nonempty UTF-8 text, up to 1 MiB."
        case .invalidManifest: return "The local manifest is invalid. The archive was not reset."
        case .changedSource: return "Original bytes no longer match the admitted local pin."
        case .archiveLimit: return "This preview holds up to 32 sources and 16 MiB of originals."
        case .invalidSelection: return "Select existing source cards again."
        }
    }
}

enum LocalHashes {
    static func sha256(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    static func strictUTF8(_ bytes: Data) throws -> String {
        let text = String(decoding: bytes, as: UTF8.self)
        guard !bytes.isEmpty, Data(text.utf8) == bytes else { throw LocalSourceError.invalidText }
        return text
    }
}

struct LocalSourceRecord: Codable, Identifiable, Equatable, Sendable {
    let id: String
    let title: String
    let sha256: String
    let byteCount: Int
    let classification: String
    let admittedAt: Date
}

struct VerifiedLocalOriginal: Sendable {
    let record: LocalSourceRecord
    let bytes: Data
}

private struct LocalManifest: Codable {
    let version: Int
    let sources: [LocalSourceRecord]
}

// The manifest is locally admitted by this app, separately from model packets.
// It is not a signature, authenticated authorship, or resistance to a compromised device.
struct LocalSourceVault {
    static let maximumSourceBytes = 1_048_576
    static let maximumArchiveBytes = 16_777_216
    let root: URL
    private(set) var records: [LocalSourceRecord]

    init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        for child in ["originals", "answers"] {
            try FileManager.default.createDirectory(
                at: root.appendingPathComponent(child, isDirectory: true),
                withIntermediateDirectories: true)
        }
        var mutableRoot = root
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try mutableRoot.setResourceValues(values)
        let manifestURL = root.appendingPathComponent("manifest.json")
        if FileManager.default.fileExists(atPath: manifestURL.path) {
            let bytes = try Self.boundedRead(manifestURL, maximum: 131_072)
            let manifest = try JSONDecoder().decode(LocalManifest.self, from: bytes)
            guard manifest.version == 1, manifest.sources.count <= 32,
                  Set(manifest.sources.map(\.id)).count == manifest.sources.count,
                  manifest.sources.allSatisfy(Self.validRecord),
                  manifest.sources.reduce(0, { $0 + $1.byteCount }) <= Self.maximumArchiveBytes else {
                throw LocalSourceError.invalidManifest
            }
            self.records = manifest.sources
        } else {
            self.records = []
        }
    }

    static func defaultRoot() throws -> URL {
        try FileManager.default.url(for: .applicationSupportDirectory,
            in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("XNETHome/v1", isDirectory: true)
    }

    static func boundedRead(_ url: URL, maximum: Int) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let bytes = try handle.read(upToCount: maximum + 1) ?? Data()
        guard bytes.count <= maximum else { throw LocalSourceError.archiveLimit }
        return bytes
    }

    mutating func admit(bytes: Data, title: String, classification: String = "private") throws -> LocalSourceRecord {
        _ = try LocalHashes.strictUTF8(bytes)
        guard bytes.count <= Self.maximumSourceBytes,
              ["private", "restricted", "public"].contains(classification),
              !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              title.utf8.count <= 256 else { throw LocalSourceError.invalidText }
        guard records.count < 32,
              records.reduce(0, { $0 + $1.byteCount }) + bytes.count <= Self.maximumArchiveBytes else {
            throw LocalSourceError.archiveLimit
        }
        let record = LocalSourceRecord(id: "src-" + UUID().uuidString.lowercased(),
            title: title, sha256: LocalHashes.sha256(bytes), byteCount: bytes.count,
            classification: classification, admittedAt: Date())
        let originalURL = url(for: record)
        // A fresh UUID path never overwrites an existing admitted source.
        guard !FileManager.default.fileExists(atPath: originalURL.path) else {
            throw LocalSourceError.invalidManifest
        }
        try Self.writeProtected(bytes, to: originalURL)
        let readBack = try Self.boundedRead(originalURL, maximum: Self.maximumSourceBytes)
        guard readBack == bytes, LocalHashes.sha256(readBack) == record.sha256 else {
            throw LocalSourceError.changedSource
        }
        let next = records + [record]
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try Self.writeProtected(try encoder.encode(LocalManifest(version: 1, sources: next)),
            to: root.appendingPathComponent("manifest.json"))
        records = next
        return record
    }

    func original(id: String) throws -> VerifiedLocalOriginal {
        guard let record = records.first(where: { $0.id == id }) else {
            throw LocalSourceError.invalidSelection
        }
        let bytes = try Self.boundedRead(url(for: record), maximum: Self.maximumSourceBytes)
        guard bytes.count == record.byteCount, LocalHashes.sha256(bytes) == record.sha256 else {
            throw LocalSourceError.changedSource
        }
        _ = try LocalHashes.strictUTF8(bytes)
        return VerifiedLocalOriginal(record: record, bytes: bytes)
    }

    func saveAnswer<T: Encodable>(_ receipt: T, id: UUID) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(receipt)
        let destination = root.appendingPathComponent("answers")
            .appendingPathComponent(id.uuidString.lowercased() + ".json")
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            throw LocalSourceError.invalidManifest
        }
        try Self.writeProtected(bytes, to: destination)
        let readBack = try Self.boundedRead(destination, maximum: bytes.count)
        guard readBack == bytes else { throw LocalSourceError.changedSource }
        return LocalHashes.sha256(readBack)
    }

    private func url(for record: LocalSourceRecord) -> URL {
        root.appendingPathComponent("originals").appendingPathComponent(record.id + ".utf8")
    }

    private static func validRecord(_ record: LocalSourceRecord) -> Bool {
        guard record.id.hasPrefix("src-"),
              let uuid = UUID(uuidString: String(record.id.dropFirst(4))),
              record.id == "src-" + uuid.uuidString.lowercased(),
              !record.title.isEmpty, record.title.utf8.count <= 256,
              record.sha256.utf8.count == 64,
              record.sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              record.byteCount > 0, record.byteCount <= maximumSourceBytes,
              ["private", "restricted", "public"].contains(record.classification) else { return false }
        return true
    }

    private static func writeProtected(_ bytes: Data, to url: URL) throws {
        #if os(iOS)
        try bytes.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try bytes.write(to: url, options: .atomic)
        #endif
    }
}
