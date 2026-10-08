import SwiftUI
import UniformTypeIdentifiers

struct HomeView: View {
    @StateObject private var model = HomeViewModel()
    @State private var showImporter = false

    var body: some View {
        NavigationStack {
            Form {
                Section("On-device intelligence") {
                    Text(model.availability)
                    Button("Check readiness") { model.checkAvailability() }
                    Text("This preview uses Apple’s local model. A source quote can be checked; an answer can still be wrong.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("My local originals") {
                    Button("Import UTF-8 text from Files") { showImporter = true }
                        .disabled(model.isGenerating)
                    TextField("Note title", text: $model.pasteTitle)
                    TextEditor(text: $model.pasteText).frame(minHeight: 90)
                        .accessibilityLabel("Paste source text")
                    Button("Save pasted note") { model.savePaste() }
                        .disabled(model.isGenerating || model.pasteText.isEmpty)
                    ForEach(model.sources) { source in
                        Toggle(isOn: Binding(
                            get: { model.selectedSourceIDs.contains(source.id) },
                            set: { model.setSource(source.id, selected: $0) })) {
                            VStack(alignment: .leading) {
                                Text(source.title)
                                Text("\(source.byteCount) bytes · \(source.classification)")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }.disabled(model.isGenerating)
                    }
                }
                Section("Ask from selected sources") {
                    TextField("Your question", text: $model.question, axis: .vertical)
                        .lineLimit(2...5).disabled(model.isGenerating)
                    Button("Find and review source cards") { model.selectCards() }
                        .disabled(model.isGenerating || model.selectedSourceIDs.isEmpty)
                    ForEach(model.cards) { card in
                        DisclosureGroup {
                            Text(card.utf8).font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                            Text("Original bytes \(card.startByte)..<\(card.endByte)")
                                .font(.caption)
                            Text(card.sha256).font(.caption2).textSelection(.enabled)
                        } label: {
                            Toggle(isOn: Binding(
                                get: { model.selectedCardIDs.contains(card.id) },
                                set: { model.setCard(card.id, selected: $0) })) {
                                Text(card.id).font(.caption)
                            }.disabled(model.isGenerating)
                        }
                    }
                    Text("\(model.selectedCardIDs.count)/4 cards selected. Smaller cards leave more room for the answer.")
                        .font(.caption)
                    Button("Ask on this iPhone") { model.ask() }.disabled(!model.canAsk)
                    if model.isGenerating {
                        ProgressView()
                        Button("Cancel request", role: .destructive) { model.cancel() }
                    }
                }
                Section("Private home gateway") {
                    Text("Remote-host route: Apple native → home 4B → home 14B. The phone-local xnet-4b BYOM lane is separate and is never selected here automatically.")
                        .font(.footnote).foregroundStyle(.secondary)
                    TextField("Private mesh IP", text: $model.remoteHost)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("TLS port", text: $model.remotePort)
                    TextField("Device ID", text: $model.remoteDeviceID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Device name", text: $model.remoteDeviceName)
                    SecureField("One-time pairing code", text: $model.remotePairingCode)
                    Button("Pair this iPhone") { model.pairRemote() }
                        .disabled(!model.canPairRemote)

                    Picker("Remote lane", selection: $model.remoteLane) {
                        Text("Home 4B").tag("home-4b")
                        Text("Home 14B").tag("home-14b")
                    }.pickerStyle(.segmented).disabled(model.isRemoteBusy)
                    TextField("Task ID", text: $model.remoteTaskID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Host-approved HCE SHA-256", text: $model.remoteHCESHA256)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if model.remoteLane == "home-4b", let hash = model.receiptHash {
                        Text("Prior Apple-native outcome").font(.caption)
                        Text(hash).font(.caption2).textSelection(.enabled)
                    }
                    Button("Send reviewed request to \(model.remoteLane)") { model.sendRemote() }
                        .disabled(!model.canSendRemote)
                    if let pending = model.remotePending {
                        Text("Pending canonical request SHA-256").font(.caption)
                        Text(pending.canonicalRequestSHA256).font(.caption2)
                            .textSelection(.enabled)
                        Button("Retry exact pending request") { model.retryRemote() }
                            .disabled(model.isRemoteBusy)
                    }
                    if model.isRemoteBusy { ProgressView() }
                    Text(model.remoteStatus).font(.callout)
                    if !model.remoteReply.isEmpty {
                        DisclosureGroup("Full home model reply") {
                            Text(model.remoteReply).font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                }
                Section("Result") {
                    Text(model.status).font(.callout)
                    if let result = model.evidence {
                        Text(result.answer).textSelection(.enabled)
                        Text("\(result.matchingQuotes) literal quotes matched; \(result.rejectedQuotes) rejected. Answer correctness is not verified.")
                            .font(.footnote).foregroundStyle(.secondary)
                        ForEach(Array(result.citations.enumerated()), id: \.offset) { index, citation in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(citation.sourceID).font(.caption).bold()
                                Text(result.matchedCitationIndexes.contains(index)
                                    ? "Literal bytes match this card" : "Rejected quote")
                                    .font(.caption)
                                Text(citation.quote).font(.callout).textSelection(.enabled)
                            }
                        }
                    }
                    if !model.rawReply.isEmpty {
                        DisclosureGroup("Full original model reply") {
                            Text(model.rawReply).font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                    if let hash = model.receiptHash {
                        Text("Local answer receipt SHA-256").font(.caption)
                        Text(hash).font(.caption2).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("XNET Home")
            .task { model.checkAvailability() }
            .fileImporter(isPresented: $showImporter,
                allowedContentTypes: [.plainText, .utf8PlainText, .json]) { result in
                switch result {
                case .success(let url): model.importFile(url)
                case .failure(let error): model.status = "File selection failed: \(error.localizedDescription)"
                }
            }
        }
    }
}
