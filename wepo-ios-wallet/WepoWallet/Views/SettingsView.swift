import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var walletManager: WalletManager
    @Environment(\.dismiss) private var dismiss
    
    @State private var showingBackupPhrase = false
    @State private var showingDeleteConfirmation = false
    @State private var biometricsEnabled = true
    @State private var notificationsEnabled = true
    @State private var privateByDefault = false
    
    var body: some View {
        NavigationView {
            List {
                // Profile Section
                Section {
                    HStack {
                        Circle()
                            .fill(Color.blue.gradient)
                            .frame(width: 50, height: 50)
                            .overlay(
                                Text(walletManager.currentWallet?.username.prefix(1).uppercased() ?? "W")
                                    .font(.title2.bold())
                                    .foregroundColor(.white)
                            )
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text(walletManager.currentWallet?.username ?? "WEPO User")
                                .font(.headline)
                            
                            Text("WEPO Wallet")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                    }
                    .padding(.vertical, 8)
                }
                
                // Security Section
                Section("Security") {
                    SettingsRow(
                        icon: "key.fill",
                        title: "Backup Recovery Phrase",
                        subtitle: "View your 12-word recovery phrase",
                        color: .orange
                    ) {
                        showingBackupPhrase = true
                    }
                    
                    HStack {
                        Image(systemName: "faceid")
                            .font(.title2)
                            .foregroundColor(.green)
                            .frame(width: 30)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Face ID / Touch ID")
                                .font(.subheadline)
                            Text("Use biometrics for authentication")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                        
                        Toggle("", isOn: $biometricsEnabled)
                    }
                    .padding(.vertical, 4)
                    
                    SettingsRow(
                        icon: "lock.rotation",
                        title: "Change Password",
                        subtitle: "Update your wallet password",
                        color: .blue
                    ) {
                        // Handle password change
                    }
                }
                
                // Privacy Section
                Section("Privacy") {
                    HStack {
                        Image(systemName: "eye.slash.fill")
                            .font(.title2)
                            .foregroundColor(.purple)
                            .frame(width: 30)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Private by Default")
                                .font(.subheadline)
                            Text("Use privacy mode for all transactions")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                        
                        Toggle("", isOn: $privateByDefault)
                    }
                    .padding(.vertical, 4)
                    
                    SettingsRow(
                        icon: "shield.fill",
                        title: "Privacy Settings",
                        subtitle: "Configure advanced privacy options",
                        color: .purple
                    ) {
                        // Handle privacy settings
                    }
                }
                
                // Notifications Section
                Section("Notifications") {
                    HStack {
                        Image(systemName: "bell.fill")
                            .font(.title2)
                            .foregroundColor(.red)
                            .frame(width: 30)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Push Notifications")
                                .font(.subheadline)
                            Text("Receive transaction and mining alerts")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                        
                        Toggle("", isOn: $notificationsEnabled)
                    }
                    .padding(.vertical, 4)
                }
                
                // Network Section
                Section("Network") {
                    SettingsRow(
                        icon: "globe",
                        title: "Network Settings",
                        subtitle: "Configure API endpoints",
                        color: .blue
                    ) {
                        // Handle network settings
                    }
                    
                    SettingsRow(
                        icon: "info.circle",
                        title: "Network Status",
                        subtitle: "View blockchain connection info",
                        color: .green
                    ) {
                        // Handle network status
                    }
                }
                
                // Support Section
                Section("Support") {
                    SettingsRow(
                        icon: "questionmark.circle",
                        title: "Help & FAQ",
                        subtitle: "Get help using WEPO Wallet",
                        color: .blue
                    ) {
                        // Handle help
                    }
                    
                    SettingsRow(
                        icon: "envelope",
                        title: "Contact Support",
                        subtitle: "Reach out to our support team",
                        color: .green
                    ) {
                        // Handle contact support
                    }
                    
                    SettingsRow(
                        icon: "doc.text",
                        title: "Terms & Privacy",
                        subtitle: "View our terms and privacy policy",
                        color: .gray
                    ) {
                        // Handle terms and privacy
                    }
                }
                
                // App Information
                Section("App Information") {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text("1.0.0")
                            .foregroundColor(.secondary)
                    }
                    
                    HStack {
                        Text("Build")
                        Spacer()
                        Text("2024.01.001")
                            .foregroundColor(.secondary)
                    }
                }
                
                // Danger Zone
                Section("Danger Zone") {
                    Button(action: {
                        walletManager.logout()
                        dismiss()
                    }) {
                        HStack {
                            Image(systemName: "rectangle.portrait.and.arrow.right")
                                .foregroundColor(.orange)
                            Text("Logout")
                                .foregroundColor(.orange)
                        }
                    }
                    
                    Button(action: {
                        showingDeleteConfirmation = true
                    }) {
                        HStack {
                            Image(systemName: "trash")
                                .foregroundColor(.red)
                            Text("Delete Wallet")
                                .foregroundColor(.red)
                        }
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .sheet(isPresented: $showingBackupPhrase) {
            BackupPhraseView()
        }
        .confirmationDialog("Delete Wallet", isPresented: $showingDeleteConfirmation) {
            Button("Delete", role: .destructive) {
                walletManager.deleteWallet()
                dismiss()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This action cannot be undone. Make sure you have backed up your recovery phrase.")
        }
    }
}

struct SettingsRow: View {
    let icon: String
    let title: String
    let subtitle: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                    .frame(width: 30)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline)
                        .foregroundColor(.primary)
                    
                    Text(subtitle)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.vertical, 4)
        }
    }
}

struct BackupPhraseView: View {
    @EnvironmentObject var walletManager: WalletManager
    @Environment(\.dismiss) private var dismiss
    @State private var seedPhrase: String = ""
    @State private var isLoading = true
    @State private var showingError = false
    @State private var errorMessage = ""
    @State private var hasAuthenticated = false
    
    var body: some View {
        NavigationView {
            VStack(spacing: 24) {
                if !hasAuthenticated {
                    AuthenticationView(onAuthenticated: {
                        hasAuthenticated = true
                        loadSeedPhrase()
                    })
                } else if isLoading {
                    VStack(spacing: 16) {
                        ProgressView()
                            .scaleEffect(1.5)
                        
                        Text("Loading Recovery Phrase...")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                } else {
                    SeedPhraseDisplayView(seedPhrase: seedPhrase)
                }
            }
            .navigationTitle("Recovery Phrase")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") {
                dismiss()
            }
        } message: {
            Text(errorMessage)
        }
    }
    
    private func loadSeedPhrase() {
        guard let wallet = walletManager.currentWallet else {
            errorMessage = "Wallet not found"
            showingError = true
            return
        }
        
        Task {
            do {
                let phrase = try await SecurityManager().loadSeedPhrase(for: wallet.address)
                await MainActor.run {
                    seedPhrase = phrase
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    errorMessage = "Failed to load recovery phrase: \(error.localizedDescription)"
                    showingError = true
                    isLoading = false
                }
            }
        }
    }
}

struct AuthenticationView: View {
    let onAuthenticated: () -> Void
    @State private var isAuthenticating = false
    
    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 16) {
                Image(systemName: "faceid")
                    .font(.system(size: 64))
                    .foregroundColor(.blue)
                
                Text("Authentication Required")
                    .font(.title2.bold())
                
                Text("Please authenticate to view your recovery phrase")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            
            Button(action: authenticate) {
                if isAuthenticating {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else {
                    Text("Authenticate")
                        .font(.headline)
                        .foregroundColor(.white)
                }
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color.blue)
            .cornerRadius(12)
            .disabled(isAuthenticating)
        }
        .padding()
    }
    
    private func authenticate() {
        isAuthenticating = true
        
        Task {
            do {
                let success = try await SecurityManager().authenticateWithBiometrics(
                    reason: "Access your wallet recovery phrase"
                )
                
                await MainActor.run {
                    if success {
                        onAuthenticated()
                    }
                    isAuthenticating = false
                }
            } catch {
                // Fallback to passcode
                do {
                    let success = try await SecurityManager().authenticateWithPasscode(
                        reason: "Access your wallet recovery phrase"
                    )
                    
                    await MainActor.run {
                        if success {
                            onAuthenticated()
                        }
                        isAuthenticating = false
                    }
                } catch {
                    await MainActor.run {
                        isAuthenticating = false
                    }
                }
            }
        }
    }
}

struct SeedPhraseDisplayView: View {
    let seedPhrase: String
    
    private var words: [String] {
        seedPhrase.components(separatedBy: " ")
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                VStack(spacing: 16) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.orange)
                    
                    Text("Your Recovery Phrase")
                        .font(.title2.bold())
                    
                    Text("Write down these 12 words in order and store them safely. Anyone with these words can access your wallet.")
                        .font(.body)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                
                LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 3), spacing: 12) {
                    ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                        HStack {
                            Text("\(index + 1).")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .frame(width: 20, alignment: .trailing)
                            Text(word)
                                .font(.body.monospaced())
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color(.systemGray6))
                        .cornerRadius(8)
                    }
                }
                .padding()
                .background(Color(.systemGray5))
                .cornerRadius(12)
                
                Button(action: {
                    UIPasteboard.general.string = seedPhrase
                }) {
                    HStack {
                        Image(systemName: "doc.on.doc")
                        Text("Copy to Clipboard")
                    }
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .cornerRadius(12)
                }
                
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text("Security Warning")
                            .font(.headline)
                            .foregroundColor(.red)
                    }
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("• Never share your recovery phrase with anyone")
                        Text("• Store it offline in a secure location")
                        Text("• Don't save it on your phone or computer")
                        Text("• Anyone with these words controls your wallet")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
                .padding()
                .background(Color.red.opacity(0.1))
                .cornerRadius(8)
            }
            .padding()
        }
    }
}

#Preview {
    SettingsView()
        .environmentObject(WalletManager())
}