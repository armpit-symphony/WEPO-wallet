import SwiftUI

struct WalletSetupView: View {
    @EnvironmentObject var walletManager: WalletManager
    @Environment(\.dismiss) private var dismiss
    
    @State private var setupMode: SetupMode = .create
    @State private var username = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var seedPhrase = ""
    @State private var generatedSeedPhrase: [String] = []
    @State private var currentStep = 1
    @State private var isLoading = false
    @State private var showingError = false
    @State private var errorMessage = ""
    @State private var showingSeedConfirmation = false
    
    enum SetupMode {
        case create, import
    }
    
    var body: some View {
        NavigationView {
            VStack {
                if setupMode == .create {
                    CreateWalletFlow()
                } else {
                    ImportWalletFlow()
                }
            }
            .navigationTitle(setupMode == .create ? "Create Wallet" : "Import Wallet")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarBackButtonHidden(true)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(setupMode == .create ? "Import" : "Create") {
                        setupMode = setupMode == .create ? .import : .create
                        resetState()
                    }
                }
            }
        }
        .alert("Error", isPresented: $showingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
    }
    
    @ViewBuilder
    private func CreateWalletFlow() -> some View {
        switch currentStep {
        case 1:
            CreateWalletStep1()
        case 2:
            CreateWalletStep2()
        case 3:
            CreateWalletStep3()
        default:
            CreateWalletStep1()
        }
    }
    
    @ViewBuilder
    private func CreateWalletStep1() -> some View {
        VStack(spacing: 24) {
            VStack(spacing: 16) {
                Image(systemName: "person.circle.fill")
                    .font(.system(size: 64))
                    .foregroundColor(.blue)
                
                Text("Create Your Identity")
                    .font(.title2.bold())
                
                Text("Choose a username and secure password for your wallet")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            
            VStack(spacing: 16) {
                TextField("Username", text: $username)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                
                SecureField("Password", text: $password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                
                SecureField("Confirm Password", text: $confirmPassword)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
            }
            
            Spacer()
            
            Button(action: {
                validateAndProceed()
            }) {
                Text("Continue")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(isValidInput ? Color.blue : Color.gray)
                    .cornerRadius(12)
            }
            .disabled(!isValidInput || isLoading)
        }
        .padding()
    }
    
    @ViewBuilder
    private func CreateWalletStep2() -> some View {
        VStack(spacing: 24) {
            VStack(spacing: 16) {
                Image(systemName: "key.fill")
                    .font(.system(size: 64))
                    .foregroundColor(.orange)
                
                Text("Your Recovery Phrase")
                    .font(.title2.bold())
                
                Text("Write down these 12 words in order. You'll need them to recover your wallet.")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            
            if !generatedSeedPhrase.isEmpty {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 3), spacing: 12) {
                    ForEach(Array(generatedSeedPhrase.enumerated()), id: \.offset) { index, word in
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
            }
            
            Spacer()
            
            VStack(spacing: 12) {
                Button(action: {
                    currentStep = 3
                }) {
                    Text("I've Written It Down")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .cornerRadius(12)
                }
                
                Button(action: {
                    generateNewSeedPhrase()
                }) {
                    Text("Generate New Phrase")
                        .font(.subheadline)
                        .foregroundColor(.blue)
                }
            }
        }
        .padding()
        .onAppear {
            if generatedSeedPhrase.isEmpty {
                generateNewSeedPhrase()
            }
        }
    }
    
    @ViewBuilder
    private func CreateWalletStep3() -> some View {
        VStack(spacing: 24) {
            VStack(spacing: 16) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 64))
                    .foregroundColor(.green)
                
                Text("Confirm Recovery Phrase")
                    .font(.title2.bold())
                
                Text("Select the words in the correct order to confirm you've saved your recovery phrase")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            
            // Add seed phrase verification UI here
            
            Spacer()
            
            Button(action: {
                createWallet()
            }) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else {
                    Text("Create Wallet")
                        .font(.headline)
                        .foregroundColor(.white)
                }
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(Color.blue)
            .cornerRadius(12)
            .disabled(isLoading)
        }
        .padding()
    }
    
    @ViewBuilder
    private func ImportWalletFlow() -> some View {
        VStack(spacing: 24) {
            VStack(spacing: 16) {
                Image(systemName: "square.and.arrow.down.fill")
                    .font(.system(size: 64))
                    .foregroundColor(.green)
                
                Text("Import Your Wallet")
                    .font(.title2.bold())
                
                Text("Enter your 12-word recovery phrase and account details")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            
            VStack(spacing: 16) {
                TextField("Username", text: $username)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                
                SecureField("Password", text: $password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                
                Text("Recovery Phrase")
                    .font(.headline)
                    .frame(maxWidth: .infinity, alignment: .leading)
                
                TextEditor(text: $seedPhrase)
                    .frame(height: 120)
                    .padding(8)
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }
            
            Spacer()
            
            Button(action: {
                importWallet()
            }) {
                if isLoading {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                } else {
                    Text("Import Wallet")
                        .font(.headline)
                        .foregroundColor(.white)
                }
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(isValidImportInput ? Color.blue : Color.gray)
            .cornerRadius(12)
            .disabled(!isValidImportInput || isLoading)
        }
        .padding()
    }
    
    private var isValidInput: Bool {
        !username.isEmpty && 
        !password.isEmpty && 
        password.count >= 8 && 
        password == confirmPassword
    }
    
    private var isValidImportInput: Bool {
        !username.isEmpty && 
        !password.isEmpty && 
        password.count >= 8 && 
        !seedPhrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    
    private func validateAndProceed() {
        guard isValidInput else {
            showError("Please fill all fields correctly")
            return
        }
        
        currentStep = 2
    }
    
    private func generateNewSeedPhrase() {
        generatedSeedPhrase = walletManager.generateSeedPhrase()
    }
    
    private func createWallet() {
        isLoading = true
        
        Task {
            do {
                let seedPhraseString = generatedSeedPhrase.joined(separator: " ")
                try await walletManager.createWallet(
                    username: username,
                    password: password,
                    seedPhrase: seedPhraseString
                )
                
                await MainActor.run {
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    showError("Failed to create wallet: \(error.localizedDescription)")
                    isLoading = false
                }
            }
        }
    }
    
    private func importWallet() {
        isLoading = true
        
        Task {
            do {
                try await walletManager.importWallet(
                    username: username,
                    password: password,
                    seedPhrase: seedPhrase.trimmingCharacters(in: .whitespacesAndNewlines)
                )
                
                await MainActor.run {
                    dismiss()
                }
            } catch {
                await MainActor.run {
                    showError("Failed to import wallet: \(error.localizedDescription)")
                    isLoading = false
                }
            }
        }
    }
    
    private func showError(_ message: String) {
        errorMessage = message
        showingError = true
    }
    
    private func resetState() {
        username = ""
        password = ""
        confirmPassword = ""
        seedPhrase = ""
        generatedSeedPhrase = []
        currentStep = 1
        isLoading = false
        showingError = false
        errorMessage = ""
    }
}

#Preview {
    WalletSetupView()
        .environmentObject(WalletManager())
}