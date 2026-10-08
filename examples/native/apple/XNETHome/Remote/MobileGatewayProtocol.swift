import Foundation
import CryptoKit

public enum MobileRemoteError: Error, LocalizedError {
    case invalidField(String)
    case oversizedMessage
    case noncanonicalMessage
    case responseMismatch
    case transportRefused
    case credentialUnavailable
    case credentialStorageFailed
    case requestInFlight
    case pendingRequestAvailable
    case noPendingRequest

    public var errorDescription: String? {
        switch self {
        case .invalidField(let field): return "Invalid mobile gateway field: \(field)."
        case .oversizedMessage: return "The mobile gateway message exceeds its byte limit."
        case .noncanonicalMessage: return "The mobile gateway message is not canonical JSON."
        case .responseMismatch: return "The response does not match the exact request."
        case .transportRefused: return "The private TLS gateway refused the request."
        case .credentialUnavailable: return "Pair this device again before sending."
        case .credentialStorageFailed: return "The pairing credential could not be stored securely."
        case .requestInFlight: return "Wait for the current gateway operation to finish."
        case .pendingRequestAvailable: return "Retry the exact pending request before sending another."
        case .noPendingRequest: return "There is no pending gateway request to retry."
        }
    }
}

/// The app should create this value only in the direct handler for a visible
/// user send control. It is an API boundary, not OS attestation of a tap.
public struct ExplicitUserSend: Hashable, Sendable {
    let identifier: UUID
    private init() { identifier = UUID() }

    @MainActor
    public static func confirmedFromUserAction() -> Self { Self() }
}

/// Pairing likewise requires an immediate, visible user action.
public struct ExplicitUserPair: Hashable, Sendable {
    let identifier: UUID
    private init() { identifier = UUID() }

    @MainActor
    public static func confirmedFromUserAction() -> Self { Self() }
}

public enum MobileWire {
    public static let pairRequestSchema = "xnet.mobile-pair-request.v1"
    public static let pairResponseSchema = "xnet.mobile-pair-response.v1"
    public static let requestSchema = "xnet.mobile-gateway-request.v1"
    public static let responseSchema = "xnet.mobile-gateway-response.v1"
    public static let orderedLanes = ["apple-native", "home-4b", "home-14b"]
    public static let maximumPairBytes = 4_096
    public static let maximumRequestBytes = 65_536
    public static let maximumResponseBytes = 131_072
    public static let maximumPromptBytes = 32_768
    public static let maximumOutputBytes = 65_536
    public static let maximumSources = 32
    public static let maximumSafeInteger = 9_007_199_254_740_991
    public static let maximumJSONDepth = 12
    public static let maximumJSONNodes = 1_024
    public static let maximumJSONContainerItems = 64

    public static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func encodeCanonical<T: Encodable>(_ value: T,
                                                     maximumBytes: Int) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard !data.isEmpty, data.count <= maximumBytes else {
            throw MobileRemoteError.oversizedMessage
        }
        return data
    }

    public static func decodeCanonical<T: Codable>(_ type: T.Type, from data: Data,
                                                   maximumBytes: Int) throws -> T {
        guard !data.isEmpty, data.count <= maximumBytes,
              String(data: data, encoding: .utf8) != nil else {
            throw MobileRemoteError.oversizedMessage
        }
        try validateJSONLexicalBounds(data)
        try validateJSONStructure(data)
        let value = try JSONDecoder().decode(type, from: data)
        guard try encodeCanonical(value, maximumBytes: maximumBytes) == data else {
            // Re-encoding also rejects duplicate fields and alternate numeric or
            // whitespace spellings accepted by Foundation's decoder.
            throw MobileRemoteError.noncanonicalMessage
        }
        return value
    }

    private struct JSONContainerBound {
        let closingByte: UInt8
        var separators = 0
        var hasContent = false
    }

    /// Refuse excessive nesting, tokens, or container entries before
    /// Foundation allocates a generic JSON tree or invokes Codable.
    private static func validateJSONLexicalBounds(_ data: Data) throws {
        var stack: [JSONContainerBound] = []
        var nodes = 0
        var inString = false
        var escaped = false
        var primitiveActive = false

        for byte in data {
            if inString {
                if escaped {
                    escaped = false
                } else if byte == 92 { // backslash
                    escaped = true
                } else if byte == 34 { // quote
                    inString = false
                }
                continue
            }

            switch byte {
            case 9, 10, 13, 32: // JSON whitespace
                primitiveActive = false
            case 34: // string (keys count toward the conservative node budget)
                primitiveActive = false
                if !stack.isEmpty { stack[stack.count - 1].hasContent = true }
                nodes += 1
                guard nodes <= maximumJSONNodes else {
                    throw MobileRemoteError.oversizedMessage
                }
                inString = true
            case 91, 123: // array or object
                primitiveActive = false
                if !stack.isEmpty { stack[stack.count - 1].hasContent = true }
                nodes += 1
                guard nodes <= maximumJSONNodes else {
                    throw MobileRemoteError.oversizedMessage
                }
                stack.append(JSONContainerBound(closingByte: byte == 91 ? 93 : 125))
                // The decoded-tree convention numbers the root as depth zero.
                guard stack.count <= maximumJSONDepth + 1 else {
                    throw MobileRemoteError.oversizedMessage
                }
            case 93, 125: // closing array or object
                primitiveActive = false
                guard let container = stack.last, container.closingByte == byte else {
                    throw MobileRemoteError.noncanonicalMessage
                }
                let items = container.hasContent ? container.separators + 1 : 0
                guard items <= maximumJSONContainerItems else {
                    throw MobileRemoteError.oversizedMessage
                }
                stack.removeLast()
            case 44: // comma at the current container level
                primitiveActive = false
                guard !stack.isEmpty else { throw MobileRemoteError.noncanonicalMessage }
                stack[stack.count - 1].separators += 1
                guard stack[stack.count - 1].separators < maximumJSONContainerItems else {
                    throw MobileRemoteError.oversizedMessage
                }
            case 58: // colon
                primitiveActive = false
            default: // number, true, false, or null; Codable checks spelling later
                if !primitiveActive {
                    if !stack.isEmpty { stack[stack.count - 1].hasContent = true }
                    nodes += 1
                    guard nodes <= maximumJSONNodes else {
                        throw MobileRemoteError.oversizedMessage
                    }
                    primitiveActive = true
                }
            }
        }
        guard !inString, !escaped, stack.isEmpty else {
            throw MobileRemoteError.noncanonicalMessage
        }
    }

    /// Bound Foundation's generic JSON tree before typed decoding accepts it.
    /// Iteration avoids adding another recursive parser stack of our own.
    private static func validateJSONStructure(_ data: Data) throws {
        let root: Any
        do {
            root = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw MobileRemoteError.noncanonicalMessage
        }
        guard root is [String: Any] else {
            throw MobileRemoteError.noncanonicalMessage
        }
        var stack: [(value: Any, depth: Int)] = [(root, 0)]
        var nodes = 0
        while let entry = stack.popLast() {
            nodes += 1
            guard nodes <= maximumJSONNodes, entry.depth <= maximumJSONDepth else {
                throw MobileRemoteError.oversizedMessage
            }
            if let object = entry.value as? [String: Any] {
                guard object.count <= maximumJSONContainerItems else {
                    throw MobileRemoteError.oversizedMessage
                }
                for (key, child) in object {
                    guard (1...128).contains(key.utf8.count) else {
                        throw MobileRemoteError.oversizedMessage
                    }
                    stack.append((child, entry.depth + 1))
                }
            } else if let array = entry.value as? [Any] {
                guard array.count <= maximumJSONContainerItems else {
                    throw MobileRemoteError.oversizedMessage
                }
                for child in array {
                    stack.append((child, entry.depth + 1))
                }
            } else if let string = entry.value as? String {
                guard string.utf8.count <= maximumResponseBytes,
                      !string.contains("\u{2028}"), !string.contains("\u{2029}") else {
                    throw MobileRemoteError.oversizedMessage
                }
            } else if entry.value is NSNumber || entry.value is NSNull {
                continue
            } else {
                throw MobileRemoteError.noncanonicalMessage
            }
        }
    }

    static func validateIdentifier(_ value: String, field: String) throws {
        let bytes = Array(value.utf8)
        let valid: (UInt8) -> Bool = { byte in
            (48...57).contains(byte) || (65...90).contains(byte)
                || (97...122).contains(byte) || [45, 46, 58, 95].contains(byte)
        }
        guard (1...128).contains(bytes.count),
              (48...57).contains(bytes[0]) || (65...90).contains(bytes[0])
                || (97...122).contains(bytes[0]),
              bytes.allSatisfy(valid) else {
            throw MobileRemoteError.invalidField(field)
        }
    }

    static func validateHash(_ value: String, field: String) throws {
        guard value.utf8.count == 64,
              value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw MobileRemoteError.invalidField(field)
        }
    }

    static func validateSecret(_ value: String, minimum: Int, maximum: Int = 256,
                               field: String) throws {
        guard (minimum...maximum).contains(value.utf8.count),
              value.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0)
                      || (97...122).contains($0) || $0 == 45 || $0 == 95
              }) else { throw MobileRemoteError.invalidField(field) }
    }

    static func validatePortableText(_ value: String, minimum: Int, maximum: Int,
                                     field: String, controlsAllowed: Bool = true) throws {
        guard (minimum...maximum).contains(value.utf8.count),
              !value.contains("\u{2028}"), !value.contains("\u{2029}"),
              controlsAllowed || value.unicodeScalars.allSatisfy({
                  $0.value >= 32 && $0.value != 127
              }) else { throw MobileRemoteError.invalidField(field) }
    }
}

public struct MobileNoAuthorityPolicy: Codable, Equatable, Sendable {
    public let toolAuthority: String
    public let vpnControl: Bool

    enum CodingKeys: String, CodingKey {
        case toolAuthority = "tool_authority"
        case vpnControl = "vpn_control"
    }

    public init() {
        toolAuthority = "none"
        vpnControl = false
    }

    public func validate() throws {
        guard toolAuthority == "none", vpnControl == false else {
            throw MobileRemoteError.invalidField("policy")
        }
    }
}

public struct MobilePairPolicy: Codable, Equatable, Sendable {
    public let explicitUserPair: Bool
    public let toolAuthority: String
    public let vpnControl: Bool

    enum CodingKeys: String, CodingKey {
        case explicitUserPair = "explicit_user_pair"
        case toolAuthority = "tool_authority"
        case vpnControl = "vpn_control"
    }

    init() {
        explicitUserPair = true
        toolAuthority = "none"
        vpnControl = false
    }
}

public struct MobileSendPolicy: Codable, Equatable, Sendable {
    public let explicitUserSend: Bool
    public let toolAuthority: String
    public let vpnControl: Bool

    enum CodingKeys: String, CodingKey {
        case explicitUserSend = "explicit_user_send"
        case toolAuthority = "tool_authority"
        case vpnControl = "vpn_control"
    }

    init() {
        explicitUserSend = true
        toolAuthority = "none"
        vpnControl = false
    }

    func validate() throws {
        guard explicitUserSend, toolAuthority == "none", vpnControl == false else {
            throw MobileRemoteError.invalidField("policy")
        }
    }
}

public struct MobilePairRequest: Codable, Equatable, Sendable {
    public let schema: String
    public let code: String
    public let deviceID: String
    public let deviceName: String
    public let policy: MobilePairPolicy

    enum CodingKeys: String, CodingKey {
        case schema, code, policy
        case deviceID = "device_id"
        case deviceName = "device_name"
    }

    public static func make(code: String, deviceID: String,
                            deviceName: String) throws -> Self {
        try MobileWire.validateSecret(code, minimum: 24, maximum: 128, field: "code")
        try MobileWire.validateIdentifier(deviceID, field: "device_id")
        try MobileWire.validatePortableText(deviceName, minimum: 1, maximum: 128,
                                            field: "device_name", controlsAllowed: false)
        return Self(schema: MobileWire.pairRequestSchema, code: code,
                    deviceID: deviceID, deviceName: deviceName,
                    policy: MobilePairPolicy())
    }
}

struct MobilePairResponse: Codable, Equatable, Sendable {
    let schema: String
    let deviceID: String
    let bearerToken: String
    let expiresAt: Int
    let policy: MobileNoAuthorityPolicy

    enum CodingKeys: String, CodingKey {
        case schema, policy
        case deviceID = "device_id"
        case bearerToken = "bearer_token"
        case expiresAt = "expires_at"
    }

    func validate(expectedDeviceID: String) throws {
        guard schema == MobileWire.pairResponseSchema, deviceID == expectedDeviceID,
              expiresAt > 0, expiresAt <= MobileWire.maximumSafeInteger else {
            throw MobileRemoteError.responseMismatch
        }
        try MobileWire.validateIdentifier(deviceID, field: "device_id")
        try MobileWire.validateSecret(bearerToken, minimum: 32, field: "bearer_token")
        try policy.validate()
    }
}

public struct MobilePairingStatus: Equatable, Sendable {
    public let deviceID: String
    public let expiresAt: Int

    init(deviceID: String, expiresAt: Int) {
        self.deviceID = deviceID
        self.expiresAt = expiresAt
    }
}

public struct MobileRoute: Codable, Equatable, Sendable {
    public let orderedLanes: [String]
    public let afterLane: String
    public let requestedLane: String
    public let parameterCeilingBillion: Int
    public let priorOutcomeSHA256: String

    enum CodingKeys: String, CodingKey {
        case orderedLanes = "ordered_lanes"
        case afterLane = "after_lane"
        case requestedLane = "requested_lane"
        case parameterCeilingBillion = "parameter_ceiling_billion"
        case priorOutcomeSHA256 = "prior_outcome_sha256"
    }

    init(requestedLane: String, priorOutcomeSHA256: String) throws {
        let expectedPrior: String
        switch requestedLane {
        case "home-4b": expectedPrior = "apple-native"
        case "home-14b": expectedPrior = "home-4b"
        default: throw MobileRemoteError.invalidField("requested_lane")
        }
        try MobileWire.validateHash(priorOutcomeSHA256, field: "prior_outcome_sha256")
        orderedLanes = MobileWire.orderedLanes
        afterLane = expectedPrior
        self.requestedLane = requestedLane
        parameterCeilingBillion = 14
        self.priorOutcomeSHA256 = priorOutcomeSHA256
    }

    func validate() throws {
        let rebuilt = try MobileRoute(requestedLane: requestedLane,
                                      priorOutcomeSHA256: priorOutcomeSHA256)
        guard self == rebuilt else { throw MobileRemoteError.invalidField("route") }
    }
}

public struct MobileRequestInput: Codable, Equatable, Sendable {
    public let taskID: String
    public let capability: String
    public let promptUTF8: String
    public let promptSHA256: String
    public let hceSHA256: String
    public let sourceSHA256: [String]

    enum CodingKeys: String, CodingKey {
        case taskID = "task_id"
        case capability
        case promptUTF8 = "prompt_utf8"
        case promptSHA256 = "prompt_sha256"
        case hceSHA256 = "hce_sha256"
        case sourceSHA256 = "source_sha256"
    }
}

public struct MobileGatewayRequest: Codable, Equatable, Sendable {
    public let schema: String
    public let requestID: String
    public let deviceID: String
    public let sequence: Int
    public let sentAt: Int
    public let route: MobileRoute
    public let input: MobileRequestInput
    public let policy: MobileSendPolicy

    enum CodingKeys: String, CodingKey {
        case schema, sequence, route, input, policy
        case requestID = "request_id"
        case deviceID = "device_id"
        case sentAt = "sent_at"
    }

    public static func make(requestID: String, deviceID: String, sequence: Int,
                            sentAt: Int, taskID: String, prompt: String,
                            hceSHA256: String, sourceSHA256: [String],
                            requestedLane: String,
                            priorOutcomeSHA256: String) throws -> Self {
        try MobileWire.validateIdentifier(requestID, field: "request_id")
        try MobileWire.validateIdentifier(deviceID, field: "device_id")
        try MobileWire.validateIdentifier(taskID, field: "task_id")
        guard (1...MobileWire.maximumSafeInteger).contains(sequence),
              (1...MobileWire.maximumSafeInteger).contains(sentAt) else {
            throw MobileRemoteError.invalidField("request bounds")
        }
        try MobileWire.validatePortableText(prompt, minimum: 1,
            maximum: MobileWire.maximumPromptBytes, field: "prompt")
        try MobileWire.validateHash(hceSHA256, field: "hce_sha256")
        guard (1...MobileWire.maximumSources).contains(sourceSHA256.count),
              Set(sourceSHA256).count == sourceSHA256.count else {
            throw MobileRemoteError.invalidField("source_sha256")
        }
        for hash in sourceSHA256 {
            try MobileWire.validateHash(hash, field: "source_sha256")
        }
        let promptData = Data(prompt.utf8)
        return Self(
            schema: MobileWire.requestSchema, requestID: requestID,
            deviceID: deviceID, sequence: sequence, sentAt: sentAt,
            route: try MobileRoute(requestedLane: requestedLane,
                                   priorOutcomeSHA256: priorOutcomeSHA256),
            input: MobileRequestInput(taskID: taskID, capability: "code", promptUTF8: prompt,
                promptSHA256: MobileWire.sha256(promptData), hceSHA256: hceSHA256,
                sourceSHA256: sourceSHA256),
            policy: MobileSendPolicy())
    }

    public func validate() throws {
        guard schema == MobileWire.requestSchema, input.capability == "code",
              (1...MobileWire.maximumSafeInteger).contains(sequence),
              (1...MobileWire.maximumSafeInteger).contains(sentAt),
              input.promptSHA256 == MobileWire.sha256(Data(input.promptUTF8.utf8)) else {
            throw MobileRemoteError.invalidField("request")
        }
        try MobileWire.validatePortableText(input.promptUTF8, minimum: 1,
            maximum: MobileWire.maximumPromptBytes, field: "prompt")
        try MobileWire.validateIdentifier(requestID, field: "request_id")
        try MobileWire.validateIdentifier(deviceID, field: "device_id")
        try MobileWire.validateIdentifier(input.taskID, field: "task_id")
        try MobileWire.validateHash(input.hceSHA256, field: "hce_sha256")
        guard (1...MobileWire.maximumSources).contains(input.sourceSHA256.count),
              Set(input.sourceSHA256).count == input.sourceSHA256.count else {
            throw MobileRemoteError.invalidField("source_sha256")
        }
        for hash in input.sourceSHA256 {
            try MobileWire.validateHash(hash, field: "source_sha256")
        }
        try route.validate()
        try policy.validate()
    }
}

public struct MobileResponseOutput: Codable, Equatable, Sendable {
    public let utf8: String
    public let sha256: String
}

public struct MobileResponseEvidence: Codable, Equatable, Sendable {
    public let hceSHA256: String
    public let sourceSHA256: [String]

    enum CodingKeys: String, CodingKey {
        case hceSHA256 = "hce_sha256"
        case sourceSHA256 = "source_sha256"
    }
}

public struct MobileGatewayResponse: Codable, Equatable, Sendable {
    public let schema: String
    public let requestID: String
    public let sequence: Int
    public let requestSHA256: String
    public let status: String
    public let selectedLane: String
    public let modelIdentitySHA256: String
    public let output: MobileResponseOutput
    public let evidence: MobileResponseEvidence
    public let policy: MobileNoAuthorityPolicy

    enum CodingKeys: String, CodingKey {
        case schema, sequence, status, output, evidence, policy
        case requestID = "request_id"
        case requestSHA256 = "request_sha256"
        case selectedLane = "selected_lane"
        case modelIdentitySHA256 = "model_identity_sha256"
    }

    public func validate(request: MobileGatewayRequest, requestData: Data) throws {
        try request.validate()
        guard schema == MobileWire.responseSchema, status == "completed",
              requestID == request.requestID, sequence == request.sequence,
              requestSHA256 == MobileWire.sha256(requestData),
              selectedLane == request.route.requestedLane,
              evidence.hceSHA256 == request.input.hceSHA256,
              evidence.sourceSHA256 == request.input.sourceSHA256,
              output.sha256 == MobileWire.sha256(Data(output.utf8.utf8)) else {
            throw MobileRemoteError.responseMismatch
        }
        try MobileWire.validatePortableText(output.utf8, minimum: 1,
            maximum: MobileWire.maximumOutputBytes, field: "output")
        try MobileWire.validateHash(modelIdentitySHA256, field: "model_identity_sha256")
        try policy.validate()
    }
}
