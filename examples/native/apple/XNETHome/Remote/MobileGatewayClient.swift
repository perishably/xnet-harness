import Foundation
import Security

public struct MobileGatewayEndpoint: Equatable, Sendable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) throws {
        guard port > 0, Self.isPrivateMeshAddress(host) else {
            throw MobileRemoteError.invalidField("gateway endpoint")
        }
        self.host = host
        self.port = port
    }

    func url(path: String) throws -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.port = Int(port)
        components.path = path
        guard let url = components.url, url.scheme == "https", url.user == nil else {
            throw MobileRemoteError.invalidField("gateway endpoint")
        }
        return url
    }

    private static func isPrivateMeshAddress(_ value: String) -> Bool {
        let fields = value.split(separator: ".", omittingEmptySubsequences: false)
        guard fields.count == 4 else { return false }
        var bytes: [Int] = []
        for field in fields {
            guard (1...3).contains(field.utf8.count),
                  field.utf8.allSatisfy({ (48...57).contains($0) }),
                  (field == "0" || !field.hasPrefix("0")),
                  let byte = Int(String(field)), (0...255).contains(byte) else { return false }
            bytes.append(byte)
        }
        return bytes[0] == 10
            || (bytes[0] == 172 && (16...31).contains(bytes[1]))
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 100 && (64...127).contains(bytes[1]))
    }
}

private final class MobileNoRedirectDelegate: NSObject, URLSessionTaskDelegate,
                                               @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private struct MobileStoredCredential: Codable {
    let deviceID: String
    let bearerToken: String
    let expiresAt: Int
}

public struct MobilePendingRequestStatus: Equatable, Sendable {
    public let requestID: String
    public let sequence: Int
    public let canonicalRequestSHA256: String

    fileprivate init(requestID: String, sequence: Int, canonicalRequestSHA256: String) {
        self.requestID = requestID
        self.sequence = sequence
        self.canonicalRequestSHA256 = canonicalRequestSHA256
    }
}

private struct MobilePendingRequest: Sendable {
    let message: MobileGatewayRequest
    let canonicalBody: Data

    var status: MobilePendingRequestStatus {
        MobilePendingRequestStatus(requestID: message.requestID, sequence: message.sequence,
            canonicalRequestSHA256: MobileWire.sha256(canonicalBody))
    }
}

private enum MobileCredentialKeychain {
    private static let service = "org.example.xnet.mobile-gateway"

    private static func account(_ endpoint: MobileGatewayEndpoint) -> String {
        endpoint.host + ":" + String(endpoint.port)
    }

    static func load(for endpoint: MobileGatewayEndpoint) throws -> MobileStoredCredential? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(endpoint),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data,
              let value = try? JSONDecoder().decode(MobileStoredCredential.self, from: data) else {
            throw MobileRemoteError.credentialStorageFailed
        }
        try MobileWire.validateIdentifier(value.deviceID, field: "stored device_id")
        try MobileWire.validateSecret(value.bearerToken, minimum: 32,
                                      field: "stored bearer_token")
        guard (1...MobileWire.maximumSafeInteger).contains(value.expiresAt) else {
            throw MobileRemoteError.credentialStorageFailed
        }
        return value
    }

    static func save(_ value: MobileStoredCredential,
                     for endpoint: MobileGatewayEndpoint) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(value)
        } catch {
            throw MobileRemoteError.credentialStorageFailed
        }
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(endpoint),
        ]
        let update = [kSecValueData as String: data]
        let updated = SecItemUpdate(identity as CFDictionary, update as CFDictionary)
        if updated == errSecSuccess { return }
        guard updated == errSecItemNotFound else {
            throw MobileRemoteError.credentialStorageFailed
        }
        var insertion = identity
        insertion[kSecValueData as String] = data
        insertion[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(insertion as CFDictionary, nil) == errSecSuccess else {
            throw MobileRemoteError.credentialStorageFailed
        }
    }

    static func delete(for endpoint: MobileGatewayEndpoint) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account(endpoint),
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw MobileRemoteError.credentialStorageFailed
        }
    }
}

/// An ephemeral client for a TLS listener already reachable through NetBird.
/// It never configures or controls the VPN and writes no credential to a file
/// or log. The bearer is kept in the this-device-only iOS Keychain.
public actor MobileGatewayClient {
    private let endpoint: MobileGatewayEndpoint
    private let session: URLSession
    private var credentialDeviceID: String?
    private var bearerToken: String?
    private var bearerExpiresAt: Int?
    private var pendingRequest: MobilePendingRequest?
    private var operationInFlight = false
    private var usedSendConfirmations: Set<UUID> = []
    private var usedPairConfirmations: Set<UUID> = []

    public init(endpoint: MobileGatewayEndpoint) throws {
        self.endpoint = endpoint
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 120
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration,
                             delegate: MobileNoRedirectDelegate(),
                             delegateQueue: nil)
        if let stored = try MobileCredentialKeychain.load(for: endpoint),
           stored.expiresAt > Int(Date().timeIntervalSince1970) {
            credentialDeviceID = stored.deviceID
            bearerToken = stored.bearerToken
            bearerExpiresAt = stored.expiresAt
        } else {
            try MobileCredentialKeychain.delete(for: endpoint)
            credentialDeviceID = nil
            bearerToken = nil
            bearerExpiresAt = nil
        }
    }

    deinit {
        session.invalidateAndCancel()
    }

    @discardableResult
    public func pair(code: String, deviceID: String, deviceName: String,
                     confirmation: ExplicitUserPair) async throws -> MobilePairingStatus {
        guard !operationInFlight else { throw MobileRemoteError.requestInFlight }
        guard usedPairConfirmations.count < 64,
              usedPairConfirmations.insert(confirmation.identifier).inserted else {
            throw MobileRemoteError.invalidField("reused user pairing confirmation")
        }
        operationInFlight = true
        defer { operationInFlight = false }
        let message = try MobilePairRequest.make(code: code, deviceID: deviceID,
            deviceName: deviceName)
        let body = try MobileWire.encodeCanonical(message,
                                                   maximumBytes: MobileWire.maximumPairBytes)
        let responseData = try await post(path: "/pair", body: body,
                                          bearer: nil,
                                          maximumResponseBytes: MobileWire.maximumPairBytes)
        let response = try MobileWire.decodeCanonical(MobilePairResponse.self,
            from: responseData, maximumBytes: MobileWire.maximumPairBytes)
        try response.validate(expectedDeviceID: deviceID)
        guard response.expiresAt > Int(Date().timeIntervalSince1970) else {
            throw MobileRemoteError.credentialUnavailable
        }
        let stored = MobileStoredCredential(deviceID: response.deviceID,
            bearerToken: response.bearerToken, expiresAt: response.expiresAt)
        // A new host credential generation makes any older uncertain request a
        // local-reconciliation concern; never replay it under the new bearer.
        pendingRequest = nil
        do {
            try MobileCredentialKeychain.save(stored, for: endpoint)
        } catch {
            clearCredentialInMemory()
            throw error
        }
        credentialDeviceID = response.deviceID
        bearerToken = response.bearerToken
        bearerExpiresAt = response.expiresAt
        return MobilePairingStatus(deviceID: response.deviceID,
                                   expiresAt: response.expiresAt)
    }

    public func send(_ message: MobileGatewayRequest,
                     confirmation: ExplicitUserSend) async throws -> MobileGatewayResponse {
        guard !operationInFlight else { throw MobileRemoteError.requestInFlight }
        guard pendingRequest == nil else { throw MobileRemoteError.pendingRequestAvailable }
        try consume(confirmation)
        operationInFlight = true
        defer { operationInFlight = false }
        try message.validate()
        let token = try currentBearer(for: message.deviceID)
        let body = try MobileWire.encodeCanonical(message,
            maximumBytes: MobileWire.maximumRequestBytes)
        let pending = MobilePendingRequest(message: message, canonicalBody: body)
        pendingRequest = pending
        let response = try await transmit(pending, bearer: token)
        pendingRequest = nil
        return response
    }

    /// Retry after a transport or response uncertainty. The exact retained
    /// canonical bytes are reused; the request is never re-encoded.
    public func retryPending(confirmation: ExplicitUserSend) async throws
        -> MobileGatewayResponse {
        guard !operationInFlight else { throw MobileRemoteError.requestInFlight }
        guard let pending = pendingRequest else { throw MobileRemoteError.noPendingRequest }
        try consume(confirmation)
        operationInFlight = true
        defer { operationInFlight = false }
        let token = try currentBearer(for: pending.message.deviceID)
        let response = try await transmit(pending, bearer: token)
        pendingRequest = nil
        return response
    }

    public func pendingRequestStatus() -> MobilePendingRequestStatus? {
        pendingRequest?.status
    }

    /// Call only after the host confirms revocation; local deletion alone does
    /// not revoke the host token and would prevent same-ID re-pairing.
    public func forgetCredentialAfterHostRevocation() throws {
        guard !operationInFlight else { throw MobileRemoteError.requestInFlight }
        try MobileCredentialKeychain.delete(for: endpoint)
        clearCredentialInMemory()
        pendingRequest = nil
    }

    private func consume(_ confirmation: ExplicitUserSend) throws {
        guard usedSendConfirmations.count < 1_024,
              usedSendConfirmations.insert(confirmation.identifier).inserted else {
            throw MobileRemoteError.invalidField("reused user send confirmation")
        }
    }

    private func clearCredentialInMemory() {
        credentialDeviceID = nil
        bearerToken = nil
        bearerExpiresAt = nil
    }

    private func currentBearer(for deviceID: String) throws -> String {
        guard let pairedDeviceID = credentialDeviceID, pairedDeviceID == deviceID,
              let token = bearerToken, let expiresAt = bearerExpiresAt,
              expiresAt > Int(Date().timeIntervalSince1970) else {
            try? MobileCredentialKeychain.delete(for: endpoint)
            clearCredentialInMemory()
            throw MobileRemoteError.credentialUnavailable
        }
        return token
    }

    private func transmit(_ pending: MobilePendingRequest, bearer: String) async throws
        -> MobileGatewayResponse {
        let responseData = try await post(path: "/request", body: pending.canonicalBody,
            bearer: bearer, maximumResponseBytes: MobileWire.maximumResponseBytes)
        let response = try MobileWire.decodeCanonical(MobileGatewayResponse.self,
            from: responseData, maximumBytes: MobileWire.maximumResponseBytes)
        try response.validate(request: pending.message, requestData: pending.canonicalBody)
        return response
    }

    private func post(path: String, body: Data, bearer: String?,
                      maximumResponseBytes: Int) async throws -> Data {
        var request = URLRequest(url: try endpoint.url(path: path))
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let bearer {
            request.setValue("Bearer " + bearer, forHTTPHeaderField: "Authorization")
        }
        let (bytes, response) = try await session.bytes(for: request)
        let mediaType = (response as? HTTPURLResponse)?
            .value(forHTTPHeaderField: "Content-Type")?
            .split(separator: ";", maxSplits: 1).first
            .map { String($0).trimmingCharacters(in: .whitespaces).lowercased() }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              mediaType == "application/json" else {
            throw MobileRemoteError.transportRefused
        }
        var result = Data()
        result.reserveCapacity(min(maximumResponseBytes, 16_384))
        for try await byte in bytes {
            guard result.count < maximumResponseBytes else {
                throw MobileRemoteError.oversizedMessage
            }
            result.append(byte)
        }
        guard !result.isEmpty else { throw MobileRemoteError.transportRefused }
        return result
    }
}
