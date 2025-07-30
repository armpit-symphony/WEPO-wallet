import SwiftUI

struct QuantumVaultView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var vaults: [VaultInfo] = []
    @State private var showingCreateVault = false
    @State private var isLoading = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Quantum Vault Header
                    VStack(spacing: 16) {
                        Image(systemName: "lock.shield.fill")
                            .font(.system(size: 48))
                            .foregroundColor(.purple)
                        
                        Text("Quantum Vault")
                            .font(.title.bold())
                        
                        Text("Privacy-protected asset storage with quantum-resistant security")
                            .font(.body)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(16)
                    
                    // Create Vault Button
                    Button(action: {
                        showingCreateVault = true
                    }) {
                        HStack {
                            Image(systemName: "plus.circle.fill")
                                .font(.title2)
                            Text("Create New Vault")
                                .font(.headline)
                        }
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.purple)
                        .cornerRadius(12)
                    }
                    
                    // Existing Vaults
                    if vaults.isEmpty {
                        VStack(spacing: 16) {
                            Image(systemName: "lock.open")
                                .font(.system(size: 32))
                                .foregroundColor(.secondary)
                            
                            Text("No Vaults Created")
                                .font(.headline)
                                .foregroundColor(.secondary)
                            
                            Text("Create your first quantum vault to securely store and protect your assets with advanced privacy features.")
                                .font(.body)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .padding(.vertical, 32)
                    } else {
                        VStack(alignment: .leading, spacing: 16) {
                            Text("Your Vaults")
                                .font(.headline)
                            
                            LazyVStack(spacing: 12) {
                                ForEach(vaults) { vault in
                                    VaultRowView(vault: vault)
                                }
                            }
                        }
                    }
                    
                    // Vault Information
                    VaultInfoSection()
                }
                .padding()
            }
            .navigationTitle("Quantum Vault")
            .refreshable {
                await loadVaults()
            }
            .onAppear {
                Task {
                    await loadVaults()
                }
            }
        }
        .sheet(isPresented: $showingCreateVault) {
            CreateVaultView()
        }
    }
    
    @MainActor
    private func loadVaults() async {
        guard let wallet = walletManager.currentWallet else { return }
        
        isLoading = true
        
        // Simulate loading vaults
        // In production, this would call the API
        await Task.sleep(1_000_000_000) // 1 second delay
        
        // Mock vault data
        vaults = [
            VaultInfo(
                id: "vault_1",
                vaultType: "privacy",
                status: "active",
                balance: 150.5,
                createdAt: "2024-01-15T10:30:00Z"
            ),
            VaultInfo(
                id: "vault_2",
                vaultType: "staking",
                status: "locked",
                balance: 1000.0,
                createdAt: "2024-01-20T14:15:00Z"
            )
        ]
        
        isLoading = false
    }
}

struct VaultRowView: View {
    let vault: VaultInfo
    @State private var showingDetails = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: vaultIcon)
                    .font(.title2)
                    .foregroundColor(vaultColor)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(vault.vaultType.capitalized)
                        .font(.headline)
                    
                    Text("Created: \(formattedDate)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                VStack(alignment: .trailing, spacing: 4) {
                    Text("\(vault.balance, specifier: "%.2f") WEPO")
                        .font(.subheadline.bold())
                        .fontDesign(.monospaced)
                    
                    Text(vault.status.capitalized)
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(statusColor.opacity(0.2))
                        .foregroundColor(statusColor)
                        .cornerRadius(4)
                }
            }
            
            HStack(spacing: 12) {
                Button(action: {
                    showingDetails = true
                }) {
                    Text("Details")
                        .font(.subheadline)
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(6)
                }
                
                Button(action: {
                    // Handle vault action
                }) {
                    Text(vault.status == "active" ? "Deposit" : "Unlock")
                        .font(.subheadline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(vaultColor)
                        .cornerRadius(6)
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
        .sheet(isPresented: $showingDetails) {
            VaultDetailView(vault: vault)
        }
    }
    
    private var vaultIcon: String {
        switch vault.vaultType {
        case "privacy":
            return "eye.slash.fill"
        case "staking":
            return "chart.line.uptrend.xyaxis"
        default:
            return "lock.fill"
        }
    }
    
    private var vaultColor: Color {
        switch vault.vaultType {
        case "privacy":
            return .purple
        case "staking":
            return .blue
        default:
            return .gray
        }
    }
    
    private var statusColor: Color {
        switch vault.status {
        case "active":
            return .green
        case "locked":
            return .orange
        case "closed":
            return .red
        default:
            return .gray
        }
    }
    
    private var formattedDate: String {
        // Simple date formatting - in production use proper date formatter
        return String(vault.createdAt.prefix(10))
    }
}

struct VaultInfoSection: View {
    @State private var showingInfo = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("About Quantum Vaults")
                    .font(.headline)
                
                Spacer()
                
                Button(action: {
                    showingInfo.toggle()
                }) {
                    Image(systemName: showingInfo ? "chevron.up" : "chevron.down")
                        .foregroundColor(.blue)
                }
            }
            
            if showingInfo {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Quantum Vaults provide:")
                        .font(.subheadline.bold())
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("• Quantum-resistant encryption")
                            .font(.caption)
                        Text("• Zero-knowledge proof privacy")
                            .font(.caption)
                        Text("• Multi-signature security")
                            .font(.caption)
                        Text("• Time-locked asset protection")
                            .font(.caption)
                        Text("• Anonymous transaction mixing")
                            .font(.caption)
                    }
                    .foregroundColor(.secondary)
                    .padding(.leading, 8)
                    
                    Text("Your assets remain under your complete control while benefiting from advanced privacy and security features.")
                        .font(.caption)
                        .foregroundColor(.blue)
                        .padding(.top, 8)
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct CreateVaultView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var vaultType = "privacy"
    @State private var initialDeposit = ""
    @State private var isCreating = false
    
    let vaultTypes = [
        ("privacy", "Privacy Vault", "Enhanced anonymity and transaction mixing"),
        ("staking", "Staking Vault", "Earn rewards while securing the network")
    ]
    
    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                Text("Create Quantum Vault")
                    .font(.title.bold())
                
                VStack(alignment: .leading, spacing: 16) {
                    Text("Select Vault Type")
                        .font(.headline)
                    
                    ForEach(vaultTypes, id: \.0) { type in
                        VaultTypeCard(
                            type: type,
                            isSelected: vaultType == type.0,
                            onSelect: { vaultType = type.0 }
                        )
                    }
                }
                
                VStack(alignment: .leading, spacing: 8) {
                    Text("Initial Deposit")
                        .font(.headline)
                    
                    TextField("Amount in WEPO", text: $initialDeposit)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .keyboardType(.decimalPad)
                    
                    Text("Minimum deposit: 10 WEPO")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Button(action: createVault) {
                    if isCreating {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    } else {
                        Text("Create Vault")
                            .font(.headline)
                            .foregroundColor(.white)
                    }
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(isValidInput ? Color.purple : Color.gray)
                .cornerRadius(12)
                .disabled(!isValidInput || isCreating)
            }
            .padding()
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }
    
    private var isValidInput: Bool {
        guard let amount = Double(initialDeposit) else { return false }
        return amount >= 10.0
    }
    
    private func createVault() {
        isCreating = true
        
        // Simulate vault creation
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            isCreating = false
            dismiss()
        }
    }
}

struct VaultTypeCard: View {
    let type: (String, String, String)
    let isSelected: Bool
    let onSelect: () -> Void
    
    var body: some View {
        Button(action: onSelect) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(type.1)
                        .font(.subheadline.bold())
                    
                    Spacer()
                    
                    if isSelected {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.purple)
                    }
                }
                
                Text(type.2)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.leading)
            }
            .padding()
            .background(isSelected ? Color.purple.opacity(0.1) : Color(.systemGray6))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? Color.purple : Color.clear, lineWidth: 2)
            )
        }
        .foregroundColor(.primary)
    }
}

struct VaultDetailView: View {
    let vault: VaultInfo
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Vault header info would go here
                    Text("Vault Details Coming Soon")
                        .font(.title2)
                        .foregroundColor(.secondary)
                }
                .padding()
            }
            .navigationTitle("\(vault.vaultType.capitalized) Vault")
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
    QuantumVaultView()
        .environmentObject(WalletManager())
}