import SwiftUI

struct ReceiveTokenView: View {
    @EnvironmentObject var walletManager: WalletManager
    @Environment(\.dismiss) private var dismiss
    
    @State private var amount = ""
    @State private var message = ""
    @State private var showingQRCode = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Header
                    VStack(spacing: 16) {
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.system(size: 48))
                            .foregroundColor(.green)
                        
                        Text("Receive WEPO")
                            .font(.title.bold())
                        
                        Text("Share your address to receive WEPO tokens")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    
                    // Address Display
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Your WEPO Address")
                            .font(.headline)
                        
                        VStack(spacing: 12) {
                            Text(walletManager.getReceiveAddress())
                                .font(.body.monospaced())
                                .padding()
                                .background(Color(.systemGray6))
                                .cornerRadius(8)
                                .multilineTextAlignment(.center)
                            
                            HStack(spacing: 16) {
                                Button(action: {
                                    UIPasteboard.general.string = walletManager.getReceiveAddress()
                                }) {
                                    HStack {
                                        Image(systemName: "doc.on.doc")
                                        Text("Copy")
                                    }
                                    .font(.subheadline)
                                    .foregroundColor(.blue)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                                    .background(Color.blue.opacity(0.1))
                                    .cornerRadius(8)
                                }
                                
                                Button(action: {
                                    showingQRCode = true
                                }) {
                                    HStack {
                                        Image(systemName: "qrcode")
                                        Text("Show QR")
                                    }
                                    .font(.subheadline)
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                                    .background(Color.green)
                                    .cornerRadius(8)
                                }
                            }
                        }
                    }
                    
                    // Payment Request (Optional)
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Payment Request (Optional)")
                            .font(.headline)
                        
                        VStack(spacing: 8) {
                            TextField("Amount (WEPO)", text: $amount)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .keyboardType(.decimalPad)
                            
                            TextField("Message or description", text: $message)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                        
                        if !amount.isEmpty || !message.isEmpty {
                            Button(action: {
                                showingQRCode = true
                            }) {
                                Text("Generate Payment QR Code")
                                    .font(.subheadline)
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding()
                                    .background(Color.blue)
                                    .cornerRadius(8)
                            }
                        }
                    }
                    
                    // Share Options
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Share Address")
                            .font(.headline)
                        
                        Button(action: shareAddress) {
                            HStack {
                                Image(systemName: "square.and.arrow.up")
                                Text("Share Address")
                            }
                            .font(.subheadline)
                            .foregroundColor(.blue)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(8)
                        }
                    }
                    
                    // Warning
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("Important")
                                .font(.headline)
                                .foregroundColor(.orange)
                        }
                        
                        Text("Only share this address with trusted parties. Anyone with this address can send you WEPO tokens, but cannot access your wallet or funds.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding()
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(8)
                    
                    Spacer()
                }
                .padding()
            }
            .navigationTitle("Receive WEPO")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .sheet(isPresented: $showingQRCode) {
            QRCodeDisplayView(
                address: walletManager.getReceiveAddress(),
                amount: amount.isEmpty ? nil : amount,
                message: message.isEmpty ? nil : message
            )
        }
    }
    
    private func shareAddress() {
        let address = walletManager.getReceiveAddress()
        let activityViewController = UIActivityViewController(
            activityItems: [address],
            applicationActivities: nil
        )
        
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let window = windowScene.windows.first {
            window.rootViewController?.present(activityViewController, animated: true)
        }
    }
}

struct QRCodeDisplayView: View {
    let address: String
    let amount: String?
    let message: String?
    
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Text("WEPO Address QR Code")
                    .font(.title2.bold())
                
                // QR Code placeholder
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(.systemGray5))
                    .frame(width: 250, height: 250)
                    .overlay(
                        VStack {
                            Image(systemName: "qrcode")
                                .font(.system(size: 64))
                                .foregroundColor(.secondary)
                            Text("QR Code")
                                .font(.headline)
                                .foregroundColor(.secondary)
                        }
                    )
                
                // Address info
                VStack(spacing: 8) {
                    Text("Address:")
                        .font(.headline)
                    
                    Text(address)
                        .font(.caption.monospaced())
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                    
                    if let amount = amount, !amount.isEmpty {
                        Text("Amount: \(amount) WEPO")
                            .font(.subheadline.bold())
                            .foregroundColor(.green)
                    }
                    
                    if let message = message, !message.isEmpty {
                        Text("Message: \(message)")
                            .font(.subheadline)
                            .foregroundColor(.blue)
                    }
                }
                
                // Action buttons
                HStack(spacing: 16) {
                    Button(action: {
                        UIPasteboard.general.string = address
                    }) {
                        HStack {
                            Image(systemName: "doc.on.doc")
                            Text("Copy Address")
                        }
                        .font(.subheadline)
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(8)
                    }
                    
                    Button(action: shareQRCode) {
                        HStack {
                            Image(systemName: "square.and.arrow.up")
                            Text("Share QR")
                        }
                        .font(.subheadline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.green)
                        .cornerRadius(8)
                    }
                }
                
                Spacer()
            }
            .padding()
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
    
    private func shareQRCode() {
        // In a real implementation, this would share the actual QR code image
        let shareText = "My WEPO Address: \(address)"
        let activityViewController = UIActivityViewController(
            activityItems: [shareText],
            applicationActivities: nil
        )
        
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let window = windowScene.windows.first {
            window.rootViewController?.present(activityViewController, animated: true)
        }
    }
}

#Preview {
    ReceiveTokenView()
        .environmentObject(WalletManager())
}