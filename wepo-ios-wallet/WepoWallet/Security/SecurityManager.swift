import Foundation
import Security
import LocalAuthentication
import CryptoKit

class SecurityManager {
    private let serviceName = "com.wepo.wallet"
    private let walletKey = "wallet_data"
    private let seedPhrasePrefix = "seed_phrase_"
    
    // MARK: - Wallet Storage
    
    func storeWallet(_ wallet: WalletData) throws {
        let data = try JSONEncoder().encode(wallet)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: walletKey,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: createAccessControl()
        ]
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecurityError.keychainError(status)
        }
    }
    
    func loadWallet() -> WalletData? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: walletKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let wallet = try? JSONDecoder().decode(WalletData.self, from: data) else {
            return nil
        }
        
        return wallet
    }
    
    func deleteWallet(for address: String) {
        // Delete wallet data
        let walletQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: walletKey
        ]
        SecItemDelete(walletQuery as CFDictionary)
        
        // Delete seed phrase
        let seedQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: seedPhrasePrefix + address
        ]
        SecItemDelete(seedQuery as CFDictionary)
    }
    
    // MARK: - Seed Phrase Storage
    
    func storeSeedPhrase(_ seedPhrase: String, for address: String) throws {
        let data = seedPhrase.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: seedPhrasePrefix + address,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: createAccessControl()
        ]
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecurityError.keychainError(status)
        }
    }
    
    func loadSeedPhrase(for address: String) async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            let context = LAContext()
            context.localizedReason = "Access your wallet recovery phrase"
            
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceName,
                kSecAttrAccount as String: seedPhrasePrefix + address,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecUseAuthenticationContext as String: context
            ]
            
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            
            guard status == errSecSuccess,
                  let data = result as? Data,
                  let seedPhrase = String(data: data, encoding: .utf8) else {
                continuation.resume(throwing: SecurityError.keychainError(status))
                return
            }
            
            continuation.resume(returning: seedPhrase)
        }
    }
    
    // MARK: - Biometric Authentication
    
    func authenticateWithBiometrics(reason: String) async throws -> Bool {
        let context = LAContext()
        var error: NSError?
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw SecurityError.biometricsNotAvailable
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else {
                    continuation.resume(throwing: error ?? SecurityError.authenticationFailed)
                }
            }
        }
    }
    
    func authenticateWithPasscode(reason: String) async throws -> Bool {
        let context = LAContext()
        
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            ) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else {
                    continuation.resume(throwing: error ?? SecurityError.authenticationFailed)
                }
            }
        }
    }
    
    // MARK: - Encryption/Decryption
    
    func encryptData(_ data: Data, with key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined!
    }
    
    func decryptData(_ encryptedData: Data, with key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    func generateEncryptionKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }
    
    // MARK: - Address Validation
    
    func validateWepoAddress(_ address: String) -> Bool {
        // WEPO addresses should start with "wepo" and be 40 characters total
        return address.hasPrefix("wepo") && address.count == 40
    }
    
    func validateBitcoinAddress(_ address: String) -> Bool {
        // Basic Bitcoin address validation
        let validPrefixes = ["1", "3", "bc1"]
        let hasValidPrefix = validPrefixes.contains { address.hasPrefix($0) }
        let validLength = address.count >= 26 && address.count <= 62
        
        return hasValidPrefix && validLength
    }
    
    // MARK: - Input Sanitization
    
    func sanitizeInput(_ input: String) -> String {
        // Remove potentially dangerous characters
        let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: " .-_@"))
        return input.components(separatedBy: allowedCharacters.inverted).joined()
    }
    
    func validateTransactionAmount(_ amount: String) -> Double? {
        // Validate and parse transaction amount
        guard let doubleValue = Double(amount),
              doubleValue > 0,
              doubleValue <= 1_000_000 else {
            return nil
        }
        
        // Limit decimal places to 8
        let multiplier = pow(10.0, 8.0)
        return round(doubleValue * multiplier) / multiplier
    }
    
    // MARK: - Private Helpers
    
    private func createAccessControl() -> SecAccessControl {
        var error: Unmanaged<CFError>?
        
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryAny],
            &error
        )
        
        guard let control = accessControl else {
            // Fallback to device passcode if biometrics not available
            return SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.devicePasscode],
                nil
            )!
        }
        
        return control
    }
}

// MARK: - Error Types

enum SecurityError: LocalizedError {
    case keychainError(OSStatus)
    case biometricsNotAvailable
    case authenticationFailed
    case encryptionFailed
    case decryptionFailed
    case invalidAddress
    case invalidAmount
    
    var errorDescription: String? {
        switch self {
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .biometricsNotAvailable:
            return "Biometric authentication is not available on this device"
        case .authenticationFailed:
            return "Authentication failed"
        case .encryptionFailed:
            return "Failed to encrypt data"
        case .decryptionFailed:
            return "Failed to decrypt data"
        case .invalidAddress:
            return "Invalid wallet address"
        case .invalidAmount:
            return "Invalid transaction amount"
        }
    }
}