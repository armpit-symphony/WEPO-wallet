import Foundation
import Alamofire
import Combine

class APIManager: ObservableObject {
    private let baseURL: String
    private let session: Session
    
    init() {
        // Use the same backend URL as the web app
        self.baseURL = "https://api.wepo.network" // This should match your production API
        
        // Configure session with security settings
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30.0
        configuration.timeoutIntervalForResource = 60.0
        
        self.session = Session(configuration: configuration)
    }
    
    // MARK: - Configuration for Development
    func setBaseURL(_ url: String) {
        // Allow dynamic URL setting for development/testing
    }
    
    // MARK: - Wallet Management
    
    func createWallet(username: String, password: String, seedPhrase: String) async throws -> CreateWalletResponse {
        let parameters: [String: Any] = [
            "username": username,
            "password": password,
            "seed_phrase": seedPhrase
        ]
        
        return try await performRequest(
            endpoint: "/api/wallet/create",
            method: .post,
            parameters: parameters,
            responseType: CreateWalletResponse.self
        )
    }
    
    func importWallet(username: String, password: String, seedPhrase: String) async throws -> CreateWalletResponse {
        let parameters: [String: Any] = [
            "username": username,
            "password": password,
            "seed_phrase": seedPhrase
        ]
        
        return try await performRequest(
            endpoint: "/api/wallet/import",
            method: .post,
            parameters: parameters,
            responseType: CreateWalletResponse.self
        )
    }
    
    func getWallet(address: String) async throws -> WalletResponse {
        return try await performRequest(
            endpoint: "/api/wallet/\(address)",
            method: .get,
            responseType: WalletResponse.self
        )
    }
    
    // MARK: - Balance and Transactions
    
    func getBalance(address: String) async throws -> BalanceResponse {
        return try await performRequest(
            endpoint: "/api/balance/\(address)",
            method: .get,
            responseType: BalanceResponse.self
        )
    }
    
    func getTransactions(address: String) async throws -> [Transaction] {
        let response: TransactionsResponse = try await performRequest(
            endpoint: "/api/transactions/\(address)",
            method: .get,
            responseType: TransactionsResponse.self
        )
        return response.transactions
    }
    
    func sendTransaction(fromAddress: String, toAddress: String, amount: Double, isPrivate: Bool = false) async throws -> Transaction {
        let parameters: [String: Any] = [
            "from_address": fromAddress,
            "to_address": toAddress,
            "amount": amount,
            "is_private": isPrivate
        ]
        
        return try await performRequest(
            endpoint: "/api/transactions/send",
            method: .post,
            parameters: parameters,
            responseType: Transaction.self
        )
    }
    
    // MARK: - Bitcoin Integration
    
    func initializeBitcoinWallet(seedPhrase: String) async throws -> BitcoinWalletResponse {
        let parameters: [String: Any] = [
            "seed_phrase": seedPhrase
        ]
        
        return try await performRequest(
            endpoint: "/api/bitcoin/wallet/init",
            method: .post,
            parameters: parameters,
            responseType: BitcoinWalletResponse.self
        )
    }
    
    func getBitcoinBalance(address: String) async throws -> Double {
        let response: BitcoinBalanceResponse = try await performRequest(
            endpoint: "/api/bitcoin/balance/\(address)",
            method: .get,
            responseType: BitcoinBalanceResponse.self
        )
        return response.balance
    }
    
    func syncBitcoinWallet(address: String) async throws -> BitcoinSyncResponse {
        let parameters: [String: Any] = [
            "address": address
        ]
        
        return try await performRequest(
            endpoint: "/api/bitcoin/wallet/sync",
            method: .post,
            parameters: parameters,
            responseType: BitcoinSyncResponse.self
        )
    }
    
    func getBitcoinUTXOs(address: String) async throws -> [UTXO] {
        let response: UTXOResponse = try await performRequest(
            endpoint: "/api/bitcoin/utxos/\(address)",
            method: .get,
            responseType: UTXOResponse.self
        )
        return response.utxos
    }
    
    // MARK: - Network Status
    
    func getNetworkStatus() async throws -> NetworkStatusResponse {
        return try await performRequest(
            endpoint: "/api/network/status",
            method: .get,
            responseType: NetworkStatusResponse.self
        )
    }
    
    // MARK: - Mining
    
    func startMining(address: String) async throws -> MiningResponse {
        let parameters: [String: Any] = [
            "address": address
        ]
        
        return try await performRequest(
            endpoint: "/api/mining/start",
            method: .post,
            parameters: parameters,
            responseType: MiningResponse.self
        )
    }
    
    func stopMining(address: String) async throws -> MiningResponse {
        let parameters: [String: Any] = [
            "address": address
        ]
        
        return try await performRequest(
            endpoint: "/api/mining/stop",
            method: .post,
            parameters: parameters,
            responseType: MiningResponse.self
        )
    }
    
    func getMiningStatus(address: String) async throws -> MiningStatusResponse {
        return try await performRequest(
            endpoint: "/api/mining/status/\(address)",
            method: .get,
            responseType: MiningStatusResponse.self
        )
    }
    
    // MARK: - Staking
    
    func startStaking(address: String, amount: Double) async throws -> StakingResponse {
        let parameters: [String: Any] = [
            "address": address,
            "amount": amount
        ]
        
        return try await performRequest(
            endpoint: "/api/staking/stake",
            method: .post,
            parameters: parameters,
            responseType: StakingResponse.self
        )
    }
    
    func unstake(address: String, amount: Double) async throws -> StakingResponse {
        let parameters: [String: Any] = [
            "address": address,
            "amount": amount
        ]
        
        return try await performRequest(
            endpoint: "/api/staking/unstake",
            method: .post,
            parameters: parameters,
            responseType: StakingResponse.self
        )
    }
    
    func getStakingInfo(address: String) async throws -> StakingInfoResponse {
        return try await performRequest(
            endpoint: "/api/staking/info/\(address)",
            method: .get,
            responseType: StakingInfoResponse.self
        )
    }
    
    // MARK: - Quantum Vault
    
    func createVault(address: String, vaultType: String, initialDeposit: Double) async throws -> VaultResponse {
        let parameters: [String: Any] = [
            "address": address,
            "vault_type": vaultType,
            "initial_deposit": initialDeposit
        ]
        
        return try await performRequest(
            endpoint: "/api/vault/create",
            method: .post,
            parameters: parameters,
            responseType: VaultResponse.self
        )
    }
    
    func getVaults(address: String) async throws -> [VaultInfo] {
        let response: VaultsResponse = try await performRequest(
            endpoint: "/api/vault/wallet/\(address)",
            method: .get,
            responseType: VaultsResponse.self
        )
        return response.vaults
    }
    
    // MARK: - Private Request Handler
    
    private func performRequest<T: Decodable>(
        endpoint: String,
        method: HTTPMethod,
        parameters: [String: Any]? = nil,
        responseType: T.Type
    ) async throws -> T {
        let url = baseURL + endpoint
        
        return try await withCheckedThrowingContinuation { continuation in
            var request = session.request(
                url,
                method: method,
                parameters: parameters,
                encoding: method == .get ? URLEncoding.default : JSONEncoding.default,
                headers: [
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                ]
            )
            
            request.responseDecodable(of: T.self) { response in
                switch response.result {
                case .success(let data):
                    continuation.resume(returning: data)
                case .failure(let error):
                    if let data = response.data,
                       let errorResponse = try? JSONDecoder().decode(APIErrorResponse.self, from: data) {
                        continuation.resume(throwing: APIError.serverError(errorResponse.detail))
                    } else {
                        continuation.resume(throwing: APIError.networkError(error.localizedDescription))
                    }
                }
            }
        }
    }
}

// MARK: - Response Models

struct CreateWalletResponse: Codable {
    let id: String
    let address: String
    let publicKey: String
    let message: String
    
    enum CodingKeys: String, CodingKey {
        case id
        case address
        case publicKey = "public_key"
        case message
    }
}

struct WalletResponse: Codable {
    let address: String
    let publicKey: String
    let balance: Double
    let createdAt: String
    
    enum CodingKeys: String, CodingKey {
        case address
        case publicKey = "public_key"
        case balance
        case createdAt = "created_at"
    }
}

struct BalanceResponse: Codable {
    let balance: Double
    let stakingBalance: Double
    let stakingRewards: Double
    
    enum CodingKeys: String, CodingKey {
        case balance
        case stakingBalance = "staking_balance"
        case stakingRewards = "staking_rewards"
    }
}

struct TransactionsResponse: Codable {
    let transactions: [Transaction]
}

struct BitcoinWalletResponse: Codable {
    let address: String
    let publicKey: String
    let message: String
    
    enum CodingKeys: String, CodingKey {
        case address
        case publicKey = "public_key"
        case message
    }
}

struct BitcoinBalanceResponse: Codable {
    let balance: Double
    let address: String
}

struct BitcoinSyncResponse: Codable {
    let success: Bool
    let message: String
    let balance: Double
}

struct UTXO: Codable {
    let txid: String
    let vout: Int
    let value: Double
    let confirmations: Int
}

struct UTXOResponse: Codable {
    let utxos: [UTXO]
}

struct NetworkStatusResponse: Codable {
    let isConnected: Bool
    let currentBlock: Int
    let peerCount: Int
    let networkHash: String
    
    enum CodingKeys: String, CodingKey {
        case isConnected = "is_connected"
        case currentBlock = "current_block"
        case peerCount = "peer_count"
        case networkHash = "network_hash"
    }
}

struct MiningResponse: Codable {
    let success: Bool
    let message: String
    let hashrate: Double?
}

struct MiningStatusResponse: Codable {
    let isActive: Bool
    let hashrate: Double
    let blocksFound: Int
    let earnings: Double
    
    enum CodingKeys: String, CodingKey {
        case isActive = "is_active"
        case hashrate
        case blocksFound = "blocks_found"
        case earnings
    }
}

struct StakingResponse: Codable {
    let success: Bool
    let message: String
    let amount: Double
}

struct StakingInfoResponse: Codable {
    let stakedAmount: Double
    let rewards: Double
    let apy: Double
    let lockPeriod: Int
    
    enum CodingKeys: String, CodingKey {
        case stakedAmount = "staked_amount"
        case rewards
        case apy
        case lockPeriod = "lock_period"
    }
}

struct VaultResponse: Codable {
    let vaultId: String
    let vaultType: String
    let status: String
    let message: String
    
    enum CodingKeys: String, CodingKey {
        case vaultId = "vault_id"
        case vaultType = "vault_type"
        case status
        case message
    }
}

struct VaultInfo: Codable, Identifiable {
    let id: String
    let vaultType: String
    let status: String
    let balance: Double
    let createdAt: String
    
    enum CodingKeys: String, CodingKey {
        case id = "vault_id"
        case vaultType = "vault_type"
        case status
        case balance
        case createdAt = "created_at"
    }
}

struct VaultsResponse: Codable {
    let vaults: [VaultInfo]
}

struct APIErrorResponse: Codable {
    let detail: String
}

// MARK: - Error Types

enum APIError: LocalizedError {
    case networkError(String)
    case serverError(String)
    case decodingError
    case invalidURL
    
    var errorDescription: String? {
        switch self {
        case .networkError(let message):
            return "Network error: \(message)"
        case .serverError(let message):
            return "Server error: \(message)"
        case .decodingError:
            return "Failed to decode response"
        case .invalidURL:
            return "Invalid URL"
        }
    }
}