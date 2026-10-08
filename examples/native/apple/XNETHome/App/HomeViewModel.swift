import SwiftUI
import Foundation

private struct NativeAnswerReceipt: Codable {
    let version = 1
    let id: UUID
    let recordedAt: Date
    let question: String
    let selectedCards: [LocalSourceCard]
    let rawCompletedReply: String
    let literalEvidence: LiteralEvidenceResult
    let backend: String
    let modelIdentity: String
    let osVersion: String
    let sdkVisiblePromptTokens: Int
    let sdkVisibleInstructionTokens: Int
    let contextSize: Int
    let outputTokenReserve: Int
    let frameworkPaddingReserve: Int
    let generationSeconds: Double
    let withinDisplayByteBudget: Bool
    let haloCalibrationActive = false
    let answerCorrectnessVerified = false
    let weightsChanged = false
    let learningPromotionActive = false
}

private struct RemoteRequestContext: Equatable {
    let deviceID: String
    let taskID: String
    let prompt: String
    let hceSHA256: String
    let sourceSHA256: [String]
}

@MainActor
final class HomeViewModel: ObservableObject {
    @Published var sources: [LocalSourceRecord] = []
    @Published var selectedSourceIDs: Set<String> = []
    @Published var selectedCardIDs: Set<String> = []
    @Published var cards: [LocalSourceCard] = []
    @Published var question = ""
    @Published var pasteTitle = "My note"
    @Published var pasteText = ""
    @Published var availability = "Not checked"
    @Published var status = "Import or paste a local source to begin."
    @Published var rawReply = ""
    @Published var evidence: LiteralEvidenceResult?
    @Published var isGenerating = false
    @Published var receiptHash: String?
    @Published var remoteHost = ""
    @Published var remotePort = "7443"
    @Published var remotePairingCode = ""
    @Published var remoteDeviceID = "iphone-1"
    @Published var remoteDeviceName = "My iPhone"
    @Published var remoteTaskID = "mobile-task-1"
    @Published var remoteHCESHA256 = ""
    @Published var remoteLane = "home-4b"
    @Published var remoteStatus = "Not paired with a home gateway."
    @Published var remoteReply = ""
    @Published var remotePending: MobilePendingRequestStatus?
    @Published var isRemoteBusy = false
    private var vault: LocalSourceVault?
    private let bridge = AppleNativeContextBridge()
    private var generationTask: Task<Void, Never>?
    private var remoteClient: MobileGatewayClient?
    private var remoteSequence = 1
    private var lastHome4ResponseSHA256: String?
    private var lastHome4Context: RemoteRequestContext?
    private var lastUsedNativeOutcomeSHA256: String?
    private var pendingRemoteRequest: MobileGatewayRequest?
    private var pendingRemoteContext: RemoteRequestContext?

    init() {
        do {
            let store = try LocalSourceVault(root: LocalSourceVault.defaultRoot())
            vault = store
            sources = store.records
        } catch { status = "Archive unavailable: \(error.localizedDescription)" }
    }

    var canAsk: Bool {
        !isGenerating && !isRemoteBusy && remotePending == nil
            && availability == "available" && vault != nil
            && !question.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !selectedCardIDs.isEmpty && selectedCardIDs.count <= 4
    }

    var canPairRemote: Bool {
        !isRemoteBusy && !isGenerating
            && !remoteHost.isEmpty && UInt16(remotePort) != nil
            && !remotePairingCode.isEmpty && !remoteDeviceID.isEmpty
            && !remoteDeviceName.isEmpty
    }

    var canSendRemote: Bool {
        let context = currentRemoteContext()
        let hasPrior: Bool
        if remoteLane == "home-4b" {
            hasPrior = receiptHash != nil && receiptHash != lastUsedNativeOutcomeSHA256
        } else {
            hasPrior = lastHome4ResponseSHA256 != nil && lastHome4Context == context
        }
        return remoteClient != nil && !isRemoteBusy && !isGenerating
            && remotePending == nil && context != nil && hasPrior
            && !question.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !remoteTaskID.isEmpty && remoteHCESHA256.utf8.count == 64
            && !selectedCardIDs.isEmpty && selectedCardIDs.count <= MobileWire.maximumSources
    }

    func checkAvailability() { availability = AppleNativeContextBridge.preflight() }

    func importFile(_ url: URL) {
        guard !isGenerating else { return }
        let accessed = url.startAccessingSecurityScopedResource()
        guard accessed else { status = "Files did not grant access to this selection."; return }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            let bytes = try LocalSourceVault.boundedRead(url,
                maximum: LocalSourceVault.maximumSourceBytes)
            try admit(bytes: bytes, title: url.lastPathComponent)
        } catch { status = "Import refused: \(error.localizedDescription)" }
    }

    func savePaste() {
        guard !isGenerating else { return }
        do {
            try admit(bytes: Data(pasteText.utf8), title: pasteTitle)
            pasteText = ""
        } catch { status = "Note refused: \(error.localizedDescription)" }
    }

    private func admit(bytes: Data, title: String) throws {
        guard var store = vault else { throw LocalSourceError.invalidManifest }
        let record = try store.admit(bytes: bytes, title: title)
        vault = store
        sources = store.records
        selectedSourceIDs.insert(record.id)
        cards = []
        selectedCardIDs = []
        status = "Original saved and re-read against its local SHA-256 pin. Select cards next."
    }

    func selectCards() {
        guard !isGenerating, let store = vault else { return }
        do {
            var candidates: [LocalSourceCard] = []
            for id in selectedSourceIDs.sorted() {
                candidates += try SourceRetrieval.cards(from: store.original(id: id))
            }
            cards = Array(SourceRetrieval.rank(candidates, query: question).prefix(16))
            selectedCardIDs = Set(cards.prefix(2).map(\.id))
            status = "Review the exact slices. Up to 4 selected cards are sent on this device."
        } catch {
            cards = []
            selectedCardIDs = []
            status = "Selection refused: \(error.localizedDescription)"
        }
    }

    func setSource(_ id: String, selected: Bool) {
        guard !isGenerating else { return }
        if selected { selectedSourceIDs.insert(id) } else { selectedSourceIDs.remove(id) }
        cards = []
        selectedCardIDs = []
    }

    func setCard(_ id: String, selected: Bool) {
        guard !isGenerating else { return }
        if selected { selectedCardIDs.insert(id) } else { selectedCardIDs.remove(id) }
    }

    func ask() {
        checkAvailability()
        guard canAsk, let store = vault else { return }
        let taskQuestion = question
        let approvedCards = cards.filter { selectedCardIDs.contains($0.id) }
        guard approvedCards.count == selectedCardIDs.count else {
            status = "Card selection changed. Select cards again."; return
        }
        do {
            // Re-read originals immediately before generation; stale or modified bytes refuse.
            for card in approvedCards {
                try SourceRetrieval.verify(card, against: store.original(id: card.originalID))
            }
        } catch { status = "Source recheck refused: \(error.localizedDescription)"; return }
        let packets = approvedCards.map {
            NativeSourcePacket(sourceID: $0.id, utf8: $0.utf8, sha256: $0.sha256,
                classification: $0.classification)
        }
        let pins = Dictionary(uniqueKeysWithValues: approvedCards.map { ($0.id, $0.sha256) })
        let classifications = Dictionary(uniqueKeysWithValues:
            approvedCards.map { ($0.id, $0.classification) })
        let outputTask = taskQuestion + """


        Reply as exactly one JSON object with these keys:
        {"answer":"your answer, or sources do not support an answer",
        "citations":[{"source_id":"exact card ID","sha256":"exact card hash","quote":"short verbatim quote"}]}
        Quotes must be verbatim from supplied cards. An unsupported answer has no citations.
        """
        rawReply = ""
        evidence = nil
        receiptHash = nil
        // A new Apple-native run starts a new ladder; an older home-4b result
        // is no longer the immediately prior outcome for a 14B escalation.
        lastHome4ResponseSHA256 = nil
        lastHome4Context = nil
        isGenerating = true
        status = "Asking Apple’s on-device model. No tool or cloud fallback is registered."
        generationTask = Task { [weak self] in
            guard let self else { return }
            defer { self.isGenerating = false; self.generationTask = nil }
            do {
                let reply = try await self.bridge.answer(task: outputTask, sources: packets,
                    trustedSourcePins: pins, trustedSourceClassifications: classifications,
                    maximumResponseTokens: 640, frameworkPaddingReserve: 256,
                    maximumAnswerBytes: 262_144)
                // Keep completed output before parsing, persistence, or checking display budgets.
                self.rawReply = reply.text
                let checked = LiteralEvidence.check(rawReply: reply.text, cards: approvedCards)
                self.evidence = checked
                let receipt = NativeAnswerReceipt(id: UUID(), recordedAt: Date(),
                    question: taskQuestion, selectedCards: approvedCards,
                    rawCompletedReply: reply.text, literalEvidence: checked,
                    backend: reply.backend, modelIdentity: reply.modelIdentity,
                    osVersion: reply.osVersion, sdkVisiblePromptTokens: reply.sdkVisiblePromptTokens,
                    sdkVisibleInstructionTokens: reply.sdkVisibleInstructionTokens,
                    contextSize: reply.contextSize, outputTokenReserve: reply.outputTokenReserve,
                    frameworkPaddingReserve: reply.callerPaddingReserve,
                    generationSeconds: reply.elapsedSeconds,
                    withinDisplayByteBudget: reply.withinOutputByteBudget)
                do {
                    self.receiptHash = try store.saveAnswer(receipt, id: receipt.id)
                    self.status = "Completed reply saved locally. Literal quotes checked; answer correctness is not graded."
                } catch {
                    self.status = "Reply retained on screen; local receipt save failed: \(error.localizedDescription)"
                }
            } catch is CancellationError {
                self.status = "Request cancelled. Any completed reply already received remains retained."
            } catch {
                self.status = "Request refused or failed: \(String(describing: error)). No fallback or automatic retry."
            }
        }
    }

    func pairRemote() {
        guard canPairRemote, let port = UInt16(remotePort) else { return }
        let confirmation = ExplicitUserPair.confirmedFromUserAction()
        let code = remotePairingCode
        let deviceID = remoteDeviceID
        let deviceName = remoteDeviceName
        isRemoteBusy = true
        remoteStatus = "Pairing with the private home gateway."
        Task { [weak self] in
            guard let self else { return }
            defer { self.isRemoteBusy = false }
            do {
                let endpoint = try MobileGatewayEndpoint(host: self.remoteHost, port: port)
                let client = try MobileGatewayClient(endpoint: endpoint)
                let paired = try await client.pair(code: code, deviceID: deviceID,
                    deviceName: deviceName, confirmation: confirmation)
                self.remoteClient = client
                self.remotePairingCode = ""
                self.remoteSequence = 1
                self.lastHome4ResponseSHA256 = nil
                self.lastHome4Context = nil
                self.lastUsedNativeOutcomeSHA256 = nil
                self.pendingRemoteRequest = nil
                self.pendingRemoteContext = nil
                self.remotePending = nil
                self.remoteStatus = "Paired as \(paired.deviceID); credential expires at \(paired.expiresAt)."
            } catch {
                self.remoteClient = nil
                self.remoteStatus = "Pairing failed: \(error.localizedDescription)"
            }
        }
    }

    func sendRemote() {
        guard canSendRemote, let client = remoteClient, let store = vault else { return }
        let approvedCards = cards.filter { selectedCardIDs.contains($0.id) }
        guard approvedCards.count == selectedCardIDs.count else {
            remoteStatus = "Card selection changed. Select cards again."
            return
        }
        do {
            for card in approvedCards {
                try SourceRetrieval.verify(card, against: store.original(id: card.originalID))
            }
            let prior: String
            if remoteLane == "home-4b" {
                guard let native = receiptHash else {
                    remoteStatus = "Save an Apple-native outcome receipt before choosing home 4B."
                    return
                }
                prior = native
            } else {
                guard let home4 = lastHome4ResponseSHA256 else {
                    remoteStatus = "Complete home 4B before choosing home 14B."
                    return
                }
                prior = home4
            }
            let context = RemoteRequestContext(
                deviceID: remoteDeviceID, taskID: remoteTaskID, prompt: question,
                hceSHA256: remoteHCESHA256,
                sourceSHA256: approvedCards.map(\.sha256))
            let request = try MobileGatewayRequest.make(
                requestID: "mobile-" + UUID().uuidString.lowercased(),
                deviceID: remoteDeviceID, sequence: remoteSequence,
                sentAt: Int(Date().timeIntervalSince1970), taskID: remoteTaskID,
                prompt: question, hceSHA256: remoteHCESHA256,
                sourceSHA256: approvedCards.map(\.sha256), requestedLane: remoteLane,
                priorOutcomeSHA256: prior)
            let confirmation = ExplicitUserSend.confirmedFromUserAction()
            pendingRemoteRequest = request
            pendingRemoteContext = context
            isRemoteBusy = true
            remoteStatus = "Sending the reviewed request to \(remoteLane)."
            Task { [weak self] in
                guard let self else { return }
                defer { self.isRemoteBusy = false }
                do {
                    let response = try await client.send(request, confirmation: confirmation)
                    try self.acceptRemote(response, request: request, context: context)
                } catch {
                    self.remotePending = await client.pendingRequestStatus()
                    if let pending = self.remotePending {
                        self.remoteStatus = "Outcome uncertain. Retry pending request \(pending.requestID) with the exact retained bytes."
                    } else {
                        self.pendingRemoteRequest = nil
                        self.pendingRemoteContext = nil
                        self.remoteStatus = "Remote request failed: \(error.localizedDescription)"
                    }
                }
            }
        } catch {
            remoteStatus = "Remote request refused locally: \(error.localizedDescription)"
        }
    }

    func retryRemote() {
        guard !isRemoteBusy, let client = remoteClient, remotePending != nil,
              let request = pendingRemoteRequest,
              let context = pendingRemoteContext else { return }
        let confirmation = ExplicitUserSend.confirmedFromUserAction()
        isRemoteBusy = true
        remoteStatus = "Retrying the exact retained canonical request."
        Task { [weak self] in
            guard let self else { return }
            defer { self.isRemoteBusy = false }
            do {
                let response = try await client.retryPending(confirmation: confirmation)
                try self.acceptRemote(response, request: request, context: context)
            } catch {
                self.remotePending = await client.pendingRequestStatus()
                self.remoteStatus = "Pending retry failed: \(error.localizedDescription)"
            }
        }
    }

    private func currentRemoteContext() -> RemoteRequestContext? {
        let approvedCards = cards.filter { selectedCardIDs.contains($0.id) }
        guard approvedCards.count == selectedCardIDs.count, !approvedCards.isEmpty else {
            return nil
        }
        return RemoteRequestContext(
            deviceID: remoteDeviceID, taskID: remoteTaskID, prompt: question,
            hceSHA256: remoteHCESHA256,
            sourceSHA256: approvedCards.map(\.sha256))
    }

    private func acceptRemote(_ response: MobileGatewayResponse,
                              request: MobileGatewayRequest,
                              context: RemoteRequestContext) throws {
        let wire = try MobileWire.encodeCanonical(response,
            maximumBytes: MobileWire.maximumResponseBytes)
        if response.selectedLane == "home-4b" {
            lastHome4ResponseSHA256 = MobileWire.sha256(wire)
            lastHome4Context = context
            lastUsedNativeOutcomeSHA256 = request.route.priorOutcomeSHA256
        } else {
            // A 4B outcome is consumed by exactly one successful 14B escalation.
            lastHome4ResponseSHA256 = nil
            lastHome4Context = nil
        }
        remoteSequence = response.sequence + 1
        remotePending = nil
        pendingRemoteRequest = nil
        pendingRemoteContext = nil
        remoteReply = response.output.utf8
        remoteStatus = response.selectedLane == "home-4b"
            ? "Completed on home-4b; its exact response hash is ready for one matching home-14b escalation."
            : "Completed on home-14b; the remote ladder is complete."
    }

    func cancel() { generationTask?.cancel() }
}
