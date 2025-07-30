import SwiftUI

struct BitcoinView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var showingAddressDetails = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Bitcoin Balance Card
                    VStack(spacing: 16) {
                        HStack {
                            Image(systemName: "bitcoinsign.circle.fill")
                                .font(.title2)
                                .foregroundColor(.orange)
                            
                            Text("Bitcoin Balance")
                                .font(.headline)
                            
                            Spacer()
                            
                            Button(action: {
                                Task {
                                    await walletManager.refreshBitcoinBalance()
                                }
                            }) {
                                Image(systemName: "arrow.clockwise")
                                    .foregroundColor(.blue)
                            }
                        }
                        
                        HStack {
                            Text("\(walletManager.bitcoinBalance, specifier: "%.8f")")
                                .font(.largeTitle.bold())
                                .fontDesign(.monospaced)
                            
                            Text("BTC")
                                .font(.title2)
                                .foregroundColor(.secondary)
                        }
                        
                        Text("≈ $\(walletManager.bitcoinBalance * 45000, specifier: "%.2f") USD")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(16)
                    
                    // Bitcoin Address Section
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Your Bitcoin Address")
                            .font(.headline)
                        
                        if !walletManager.bitcoinAddress.isEmpty {
                            VStack(spacing: 12) {
                                HStack {
                                    Text(walletManager.bitcoinAddress)
                                        .font(.caption.monospaced())
                                        .foregroundColor(.secondary)
                                        .lineLimit(2)
                                        .truncationMode(.middle)
                                    
                                    Spacer()
                                    
                                    Button(action: {
                                        UIPasteboard.general.string = walletManager.bitcoinAddress
                                    }) {
                                        Image(systemName: "doc.on.doc")
                                            .foregroundColor(.blue)
                                    }
                                }
                                
                                Button(action: {
                                    showingAddressDetails = true
                                }) {
                                    Text("Show QR Code")
                                        .font(.subheadline)
                                        .foregroundColor(.blue)
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 8)
                                        .background(Color.blue.opacity(0.1))
                                        .cornerRadius(8)
                                }
                            }
                        } else {
                            Text("Bitcoin wallet not initialized")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    
                    // Recovery Information
                    BitcoinRecoveryInfoView()
                    
                    // Transaction History (placeholder)
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Bitcoin Transactions")
                            .font(.headline)
                        
                        Text("Coming soon - Bitcoin transaction history will be displayed here")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.vertical, 32)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                }
                .padding()
            }
            .navigationTitle("Bitcoin")
            .refreshable {
                await walletManager.refreshBitcoinBalance()
            }
        }
        .sheet(isPresented: $showingAddressDetails) {
            BitcoinAddressDetailView(address: walletManager.bitcoinAddress)
        }
    }
}

struct BitcoinRecoveryInfoView: View {
    @State private var showingRecoveryInfo = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "info.circle.fill")
                    .foregroundColor(.blue)
                
                Text("Recovery Information")
                    .font(.headline)
                
                Spacer()
                
                Button(action: {
                    showingRecoveryInfo.toggle()
                }) {
                    Image(systemName: showingRecoveryInfo ? "chevron.up" : "chevron.down")
                        .foregroundColor(.blue)
                }
            }
            
            if showingRecoveryInfo {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Your Bitcoin wallet is self-custodial and follows BIP-44 standard:")
                        .font(.subheadline)
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("• Derivation Path: m/44'/0'/0'/0/0")
                            .font(.caption.monospaced())
                        Text("• Compatible with most Bitcoin wallets")
                            .font(.caption)
                        Text("• Use your 12-word seed phrase to recover")
                            .font(.caption)
                    }
                    .foregroundColor(.secondary)
                    .padding(.leading, 8)
                }
                .padding(.top, 8)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct BitcoinAddressDetailView: View {
    let address: String
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Text("Bitcoin Address")
                    .font(.title2.bold())
                
                // QR Code placeholder
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(.systemGray5))
                    .frame(width: 200, height: 200)
                    .overlay(
                        VStack {
                            Image(systemName: "qrcode")
                                .font(.title)
                                .foregroundColor(.secondary)
                            Text("QR Code")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    )
                
                VStack(spacing: 12) {
                    Text("Address:")
                        .font(.headline)
                    
                    Text(address)
                        .font(.body.monospaced())
                        .multilineTextAlignment(.center)
                        .padding()
                        .background(Color(.systemGray6))
                        .cornerRadius(8)
                    
                    Button(action: {
                        UIPasteboard.general.string = address
                    }) {
                        Text("Copy Address")
                            .font(.headline)
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.blue)
                            .cornerRadius(12)
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
}

#Preview {
    BitcoinView()
        .environmentObject(WalletManager())
}