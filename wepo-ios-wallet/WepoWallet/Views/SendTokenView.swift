import SwiftUI

struct SendTokenView: View {
    @EnvironmentObject var walletManager: WalletManager
    @Environment(\.dismiss) private var dismiss
    
    @State private var recipientAddress = ""
    @State private var amount = ""
    @State private var isPrivateMode = false
    @State private var isSending = false
    @State private var showingConfirmation = false
    @State private var showingError = false
    @State private var errorMessage = ""
    @State private var showingScanner = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Header
                    VStack(spacing: 16) {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 48))
                            .foregroundColor(.blue)
                        
                        Text("Send WEPO")
                            .font(.title.bold())
                        
                        Text("Available Balance: \(walletManager.balance, specifier: "%.6f") WEPO")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                    
                    // Recipient Address
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Recipient Address")
                            .font(.headline)
                        
                        HStack {
                            TextField("Enter WEPO address", text: $recipientAddress)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .autocapitalization(.none)
                                .disableAutocorrection(true)
                            
                            Button(action: {
                                showingScanner = true
                            }) {
                                Image(systemName: "qrcode.viewfinder")
                                    .font(.title2)
                                    .foregroundColor(.blue)
                            }
                        }
                        
                        if !recipientAddress.isEmpty && !isValidAddress {
                            Text("Invalid WEPO address format")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                    
                    // Amount
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Amount")
                            .font(.headline)
                        
                        TextField("0.000000", text: $amount)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .keyboardType(.decimalPad)
                            .font(.title3.monospaced())
                        
                        HStack {
                            Button("25%") { setPercentage(0.25) }
                            Button("50%") { setPercentage(0.50) }
                            Button("75%") { setPercentage(0.75) }
                            Button("Max") { setPercentage(1.0) }
                        }
                        .buttonStyle(PercentageButtonStyle())
                        
                        if let amountValue = Double(amount), amountValue > walletManager.balance {
                            Text("Insufficient balance")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                    
                    // Privacy Mode
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Toggle("Private Transaction", isOn: $isPrivateMode)
                                .font(.headline)
                        }
                        
                        if isPrivateMode {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Image(systemName: "lock.shield.fill")
                                        .foregroundColor(.purple)
                                    Text("Enhanced Privacy Mode")
                                        .font(.subheadline.bold())
                                        .foregroundColor(.purple)
                                }
                                
                                Text("Your transaction will be mixed through quantum vaults for enhanced anonymity. Additional network fees may apply.")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            .padding()
                            .background(Color.purple.opacity(0.1))
                            .cornerRadius(8)
                        }
                    }
                    
                    // Transaction Summary
                    if isValidTransaction {
                        TransactionSummaryView(
                            amount: Double(amount) ?? 0,
                            recipient: recipientAddress,
                            isPrivate: isPrivateMode,
                            fee: calculateFee()
                        )
                    }
                    
                    Spacer()
                    
                    // Send Button
                    Button(action: {
                        showingConfirmation = true
                    }) {
                        if isSending {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        } else {
                            Text("Send WEPO")
                                .font(.headline)
                                .foregroundColor(.white)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(isValidTransaction ? Color.blue : Color.gray)
                    .cornerRadius(12)
                    .disabled(!isValidTransaction || isSending)
                }
                .padding()
            }
            .navigationTitle("Send WEPO")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
        .confirmationDialog("Confirm Transaction", isPresented: $showingConfirmation, titleVisibility: .visible) {
            Button("Send") {
                sendTransaction()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Send \(amount) WEPO to \(recipientAddress.prefix(20))...?")
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
        .sheet(isPresented: $showingScanner) {
            QRCodeScannerView { scannedAddress in
                recipientAddress = scannedAddress
                showingScanner = false
            }
        }
    }
    
    private var isValidAddress: Bool {
        SecurityManager().validateWepoAddress(recipientAddress.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    
    private var isValidTransaction: Bool {
        guard let amountValue = Double(amount) else { return false }
        return isValidAddress && 
               amountValue > 0 && 
               amountValue <= walletManager.balance &&
               !recipientAddress.isEmpty
    }
    
    private func setPercentage(_ percentage: Double) {
        let calculatedAmount = walletManager.balance * percentage
        amount = String(format: "%.6f", calculatedAmount)
    }
    
    private func calculateFee() -> Double {
        // WEPO has no fees, but privacy mode might have network costs
        return isPrivateMode ? 0.001 : 0.0
    }
    
    private func sendTransaction() {
        guard let amountValue = Double(amount) else { return }
        
        isSending = true
        
        Task {
            do {
                try await walletManager.sendTokens(
                    to: recipientAddress.trimmingCharacters(in: .whitespacesAndNewlines),
                    amount: amountValue,
                    isPrivate: isPrivateMode
                )
                
                await MainActor.run {
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    showingError = true
                    isSending = false
                }
            }
        }
    }
}

struct TransactionSummaryView: View {
    let amount: Double
    let recipient: String
    let isPrivate: Bool
    let fee: Double
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Transaction Summary")
                .font(.headline)
            
            VStack(spacing: 8) {
                HStack {
                    Text("Amount:")
                        .foregroundColor(.secondary)
                    Spacer()
                    Text("\(amount, specifier: "%.6f") WEPO")
                        .font(.monospaced())
                }
                
                HStack {
                    Text("Network Fee:")
                        .foregroundColor(.secondary)
                    Spacer()
                    Text("\(fee, specifier: "%.6f") WEPO")
                        .font(.monospaced())
                        .foregroundColor(fee == 0 ? .green : .primary)
                }
                
                Divider()
                
                HStack {
                    Text("Total:")
                        .font(.headline)
                    Spacer()
                    Text("\(amount + fee, specifier: "%.6f") WEPO")
                        .font(.headline.monospaced())
                }
                
                if isPrivate {
                    HStack {
                        Image(systemName: "eye.slash")
                            .foregroundColor(.purple)
                        Text("Private Transaction")
                            .font(.caption)
                            .foregroundColor(.purple)
                        Spacer()
                    }
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct PercentageButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.caption.bold())
            .foregroundColor(.blue)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Color.blue.opacity(0.1))
            .cornerRadius(6)
            .scaleEffect(configuration.isPressed ? 0.95 : 1.0)
    }
}

struct QRCodeScannerView: View {
    let onScan: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            VStack {
                // QR Scanner placeholder
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(.systemGray5))
                    .frame(height: 300)
                    .overlay(
                        VStack {
                            Image(systemName: "qrcode.viewfinder")
                                .font(.system(size: 48))
                                .foregroundColor(.secondary)
                            Text("QR Code Scanner")
                                .font(.headline)
                                .foregroundColor(.secondary)
                            Text("Camera integration coming soon")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    )
                
                Text("Position QR code within the frame to scan WEPO address")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding()
                
                Spacer()
            }
            .padding()
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }
}

#Preview {
    SendTokenView()
        .environmentObject(WalletManager())
}