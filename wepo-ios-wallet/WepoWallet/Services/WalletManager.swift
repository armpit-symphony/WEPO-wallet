import Foundation
import SwiftUI
import CryptoKit
import Combine

@MainActor
class WalletManager: ObservableObject {
    @Published var hasWallet = false
    @Published var isLoggedIn = false
    @Published var balance: Double = 0.0
    @Published var stakingBalance: Double = 0.0
    @Published var stakingRewards: Double = 0.0
    @Published var transactions: [Transaction] = []
    @Published var currentBlock: Int = 0
    @Published var isConnected = false
    @Published var bitcoinBalance: Double = 0.0
    @Published var bitcoinAddress = ""
    
    private let apiManager = APIManager()
    private let securityManager = SecurityManager()
    private var refreshTimer: Timer?
    
    // Wallet data
    private var currentWallet: WalletData?
    private var seedPhrase: String?
    
    // Add currentWallet as a published property for access from views
    var currentWallet: WalletData? {
        return self.currentWallet
    }
    
    init() {
        startPeriodicRefresh()
    }
    
    deinit {
        refreshTimer?.invalidate()
    }
    
    // MARK: - Wallet Management
    
    func loadWallet() {
        // Check if wallet exists in Keychain
        if let storedWallet = securityManager.loadWallet() {
            hasWallet = true
            currentWallet = storedWallet
            
            Task {
                await refreshData()
            }
        }
    }
    
    func createWallet(username: String, password: String, seedPhrase: String) async throws {
        // Validate seed phrase
        let words = seedPhrase.components(separatedBy: " ")
        guard words.count == 12 else {
            throw WalletError.invalidSeedPhrase
        }
        
        // Generate wallet address from seed phrase
        let walletAddress = try await generateWalletAddress(from: seedPhrase)
        
        // Create wallet on backend
        let walletData = try await apiManager.createWallet(
            username: username,
            password: password,
            seedPhrase: seedPhrase
        )
        
        // Store wallet securely
        let wallet = WalletData(
            id: walletData.id,
            username: username,
            address: walletAddress,
            publicKey: walletData.publicKey,
            createdAt: Date()
        )
        
        try securityManager.storeWallet(wallet)
        try securityManager.storeSeedPhrase(seedPhrase, for: walletAddress)
        
        // Update state
        hasWallet = true
        isLoggedIn = true
        currentWallet = wallet
        self.seedPhrase = seedPhrase
        
        // Initialize Bitcoin wallet
        await initializeBitcoinWallet()
        
        // Refresh data
        await refreshData()
    }
    
    func importWallet(username: String, password: String, seedPhrase: String) async throws {
        // Validate seed phrase
        let words = seedPhrase.components(separatedBy: " ")
        guard words.count == 12 else {
            throw WalletError.invalidSeedPhrase
        }
        
        // Generate wallet address from seed phrase
        let walletAddress = try await generateWalletAddress(from: seedPhrase)
        
        // Try to import wallet on backend
        let walletData = try await apiManager.importWallet(
            username: username,
            password: password,
            seedPhrase: seedPhrase
        )
        
        // Store wallet securely
        let wallet = WalletData(
            id: walletData.id,
            username: username,
            address: walletAddress,
            publicKey: walletData.publicKey,
            createdAt: Date()
        )
        
        try securityManager.storeWallet(wallet)
        try securityManager.storeSeedPhrase(seedPhrase, for: walletAddress)
        
        // Update state
        hasWallet = true
        isLoggedIn = true
        currentWallet = wallet
        self.seedPhrase = seedPhrase
        
        // Initialize Bitcoin wallet
        await initializeBitcoinWallet()
        
        // Refresh data
        await refreshData()
    }
    
    func logout() {
        isLoggedIn = false
        currentWallet = nil
        seedPhrase = nil
        balance = 0.0
        stakingBalance = 0.0
        stakingRewards = 0.0
        transactions.removeAll()
        bitcoinBalance = 0.0
        bitcoinAddress = ""
    }
    
    func deleteWallet() {
        guard let wallet = currentWallet else { return }
        
        securityManager.deleteWallet(for: wallet.address)
        hasWallet = false
        isLoggedIn = false
        currentWallet = nil
        seedPhrase = nil
        balance = 0.0
        stakingBalance = 0.0
        stakingRewards = 0.0
        transactions.removeAll()
        bitcoinBalance = 0.0
        bitcoinAddress = ""
    }
    
    // MARK: - Seed Phrase Generation
    
    func generateSeedPhrase() -> [String] {
        let words = BIP39WordList.words
        var seedWords: [String] = []
        
        for _ in 0..<12 {
            let randomIndex = Int.random(in: 0..<words.count)
            seedWords.append(words[randomIndex])
        }
        
        return seedWords
    }
    
    // MARK: - Transaction Operations
    
    func sendTokens(to address: String, amount: Double, isPrivate: Bool = false) async throws {
        guard let wallet = currentWallet else {
            throw WalletError.walletNotFound
        }
        
        guard amount > 0 && amount <= balance else {
            throw WalletError.insufficientBalance
        }
        
        let transaction = try await apiManager.sendTransaction(
            fromAddress: wallet.address,
            toAddress: address,
            amount: amount,
            isPrivate: isPrivate
        )
        
        // Update local balance optimistically
        balance -= amount
        
        // Add transaction to local history
        transactions.insert(transaction, at: 0)
        
        // Refresh after a delay to get accurate data
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            Task {
                await self.refreshBalance()
                await self.refreshTransactions()
            }
        }
    }
    
    func getReceiveAddress() -> String {
        return currentWallet?.address ?? ""
    }
    
    // MARK: - Bitcoin Integration
    
    private func initializeBitcoinWallet() async {
        guard let seedPhrase = seedPhrase else { return }
        
        do {
            let bitcoinWallet = try await apiManager.initializeBitcoinWallet(seedPhrase: seedPhrase)
            bitcoinAddress = bitcoinWallet.address
            await refreshBitcoinBalance()
        } catch {
            print("Failed to initialize Bitcoin wallet: \(error)")
        }
    }
    
    func refreshBitcoinBalance() async {
        guard !bitcoinAddress.isEmpty else { return }
        
        do {
            bitcoinBalance = try await apiManager.getBitcoinBalance(address: bitcoinAddress)
        } catch {
            print("Failed to refresh Bitcoin balance: \(error)")
        }
    }
    
    // MARK: - Data Refresh
    
    func refreshData() async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.refreshBalance() }
            group.addTask { await self.refreshTransactions() }
            group.addTask { await self.refreshNetworkStatus() }
            group.addTask { await self.refreshBitcoinBalance() }
        }
    }
    
    func refreshBalance() async {
        guard let wallet = currentWallet else { return }
        
        do {
            let balanceData = try await apiManager.getBalance(address: wallet.address)
            balance = balanceData.balance
            stakingBalance = balanceData.stakingBalance
            stakingRewards = balanceData.stakingRewards
        } catch {
            print("Failed to refresh balance: \(error)")
        }
    }
    
    func refreshTransactions() async {
        guard let wallet = currentWallet else { return }
        
        do {
            transactions = try await apiManager.getTransactions(address: wallet.address)
        } catch {
            print("Failed to refresh transactions: \(error)")
        }
    }
    
    func refreshNetworkStatus() async {
        do {
            let status = try await apiManager.getNetworkStatus()
            isConnected = status.isConnected
            currentBlock = status.currentBlock
        } catch {
            print("Failed to refresh network status: \(error)")
            isConnected = false
        }
    }
    
    // MARK: - Private Methods
    
    private func generateWalletAddress(from seedPhrase: String) async throws -> String {
        // Use the seed phrase to generate a deterministic wallet address
        let data = Data(seedPhrase.utf8)
        let hash = SHA256.hash(data: data)
        let hashString = hash.compactMap { String(format: "%02x", $0) }.joined()
        
        // Take first 40 characters to create an address-like format
        let address = "wepo" + String(hashString.prefix(36))
        return address
    }
    
    private func startPeriodicRefresh() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { _ in
            Task {
                await self.refreshData()
            }
        }
    }
}

// MARK: - Supporting Types

struct WalletData: Codable {
    let id: String
    let username: String
    let address: String
    let publicKey: String
    let createdAt: Date
}

struct Transaction: Codable, Identifiable {
    let id: String
    let type: TransactionType
    let amount: Double
    let fromAddress: String
    let toAddress: String
    let timestamp: Date
    let status: TransactionStatus
    let txHash: String
}

enum TransactionType: String, Codable {
    case sent = "sent"
    case received = "received"
}

enum TransactionStatus: String, Codable {
    case pending = "pending"
    case confirmed = "confirmed"
    case failed = "failed"
}

enum WalletError: LocalizedError {
    case walletNotFound
    case invalidSeedPhrase
    case insufficientBalance
    case networkError
    case invalidAddress
    
    var errorDescription: String? {
        switch self {
        case .walletNotFound:
            return "Wallet not found"
        case .invalidSeedPhrase:
            return "Invalid seed phrase. Please check and try again."
        case .insufficientBalance:
            return "Insufficient balance for this transaction"
        case .networkError:
            return "Network error. Please check your connection."
        case .invalidAddress:
            return "Invalid wallet address"
        }
    }
}

// BIP39 Word List (simplified - in production, use the full list)
struct BIP39WordList {
    static let words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
        "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
        "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
        "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
        "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
        "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing",
        "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle",
        "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
        "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve",
        "april", "arcade", "arch", "arctic", "area", "arena", "argue", "arm",
        "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow",
        "art", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist",
        "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract",
        "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average",
        "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward",
        "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
        "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel",
        "base", "basic", "basket", "battle", "beach", "bean", "beauty", "become",
        "beef", "before", "begin", "behave", "behind", "believe", "below", "belt"
    ]
}