package com.wepo.wallet.data.repository

import com.wepo.wallet.data.local.SecurityManager
import com.wepo.wallet.data.model.*
import com.wepo.wallet.data.remote.WepoApiService
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class WalletRepository @Inject constructor(
    private val apiService: WepoApiService,
    private val securityManager: SecurityManager
) {
    
    private val _walletState = MutableStateFlow<WalletData?>(null)
    val walletState: StateFlow<WalletData?> = _walletState.asStateFlow()
    
    private val _balance = MutableStateFlow(0.0)
    val balance: StateFlow<Double> = _balance.asStateFlow()
    
    private val _bitcoinBalance = MutableStateFlow(0.0)
    val bitcoinBalance: StateFlow<Double> = _bitcoinBalance.asStateFlow()
    
    private val _transactions = MutableStateFlow<List<Transaction>>(emptyList())
    val transactions: StateFlow<List<Transaction>> = _transactions.asStateFlow()
    
    private val _networkStatus = MutableStateFlow(
        NetworkStatus(false, 0, 0, "")
    )
    val networkStatus: StateFlow<NetworkStatus> = _networkStatus.asStateFlow()
    
    private val _stakingInfo = MutableStateFlow(
        StakingInfo(0.0, 0.0, 0.0, 0)
    )
    val stakingInfo: StateFlow<StakingInfo> = _stakingInfo.asStateFlow()
    
    private val _miningStatus = MutableStateFlow(
        MiningStatus(false, 0.0, 0, 0.0)
    )
    val miningStatus: StateFlow<MiningStatus> = _miningStatus.asStateFlow()
    
    // Wallet Management
    suspend fun createWallet(username: String, password: String, seedPhrase: String): Result<WalletData> {
        return try {
            val response = apiService.createWallet(
                mapOf(
                    "username" to username,
                    "password" to password,
                    "seed_phrase" to seedPhrase
                )
            )
            
            val walletData = WalletData(
                id = response.id,
                username = username,
                address = response.address,
                publicKey = response.publicKey
            )
            
            // Store wallet securely
            securityManager.storeWallet(walletData)
            securityManager.storeSeedPhrase(seedPhrase, walletData.address)
            
            _walletState.value = walletData
            
            // Initialize Bitcoin wallet
            initializeBitcoinWallet(seedPhrase)
            
            Result.success(walletData)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun importWallet(username: String, password: String, seedPhrase: String): Result<WalletData> {
        return try {
            val response = apiService.importWallet(
                mapOf(
                    "username" to username,
                    "password" to password,
                    "seed_phrase" to seedPhrase
                )
            )
            
            val walletData = WalletData(
                id = response.id,
                username = username,
                address = response.address,
                publicKey = response.publicKey
            )
            
            // Store wallet securely
            securityManager.storeWallet(walletData)
            securityManager.storeSeedPhrase(seedPhrase, walletData.address)
            
            _walletState.value = walletData
            
            // Initialize Bitcoin wallet
            initializeBitcoinWallet(seedPhrase)
            
            Result.success(walletData)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    fun loadWallet(): WalletData? {
        val wallet = securityManager.loadWallet()
        _walletState.value = wallet
        return wallet
    }
    
    fun logout() {
        _walletState.value = null
        _balance.value = 0.0
        _bitcoinBalance.value = 0.0
        _transactions.value = emptyList()
    }
    
    fun deleteWallet() {
        _walletState.value?.let { wallet ->
            securityManager.deleteWallet(wallet.address)
        }
        logout()
    }
    
    // Balance Management
    suspend fun refreshBalance(): Result<Double> {
        return try {
            val wallet = _walletState.value ?: return Result.failure(Exception("No wallet found"))
            val response = apiService.getBalance(wallet.address)
            _balance.value = response.balance
            
            val stakingInfo = StakingInfo(
                stakedAmount = response.stakingBalance,
                rewards = response.stakingRewards,
                apy = 12.5, // Default APY
                lockPeriod = 30
            )
            _stakingInfo.value = stakingInfo
            
            Result.success(response.balance)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Transaction Management
    suspend fun sendTransaction(toAddress: String, amount: Double, isPrivate: Boolean): Result<Transaction> {
        return try {
            val wallet = _walletState.value ?: return Result.failure(Exception("No wallet found"))
            
            val transaction = apiService.sendTransaction(
                mapOf(
                    "from_address" to wallet.address,
                    "to_address" to toAddress,
                    "amount" to amount,
                    "is_private" to isPrivate
                )
            )
            
            // Update local balance optimistically
            _balance.value = _balance.value - amount
            
            // Add transaction to history
            val currentTransactions = _transactions.value.toMutableList()
            currentTransactions.add(0, transaction)
            _transactions.value = currentTransactions
            
            Result.success(transaction)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun refreshTransactions(): Result<List<Transaction>> {
        return try {
            val wallet = _walletState.value ?: return Result.failure(Exception("No wallet found"))
            val response = apiService.getTransactions(wallet.address)
            _transactions.value = response.transactions
            Result.success(response.transactions)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Bitcoin Integration
    private suspend fun initializeBitcoinWallet(seedPhrase: String) {
        try {
            apiService.initializeBitcoinWallet(
                mapOf("seed_phrase" to seedPhrase)
            )
            refreshBitcoinBalance()
        } catch (e: Exception) {
            // Handle Bitcoin wallet initialization error
        }
    }
    
    suspend fun refreshBitcoinBalance(): Result<Double> {
        return try {
            val wallet = _walletState.value ?: return Result.failure(Exception("No wallet found"))
            // For Bitcoin, we'll use a derived address
            val bitcoinAddress = generateBitcoinAddress(wallet.address)
            val response = apiService.getBitcoinBalance(bitcoinAddress)
            _bitcoinBalance.value = response.balance
            Result.success(response.balance)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Network Status
    suspend fun refreshNetworkStatus(): Result<NetworkStatus> {
        return try {
            val response = apiService.getNetworkStatus()
            val networkStatus = NetworkStatus(
                isConnected = response.isConnected,
                currentBlock = response.currentBlock,
                peerCount = response.peerCount,
                networkHash = response.networkHash
            )
            _networkStatus.value = networkStatus
            Result.success(networkStatus)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Mining
    suspend fun toggleMining(start: Boolean): Result<Boolean> {
        return try {
            val wallet = _walletState.value ?: return Result.failure(Exception("No wallet found"))
            
            if (start) {
                apiService.startMining(mapOf("address" to wallet.address))
                _miningStatus.value = _miningStatus.value.copy(isActive = true)
            } else {
                apiService.stopMining(mapOf("address" to wallet.address))
                _miningStatus.value = _miningStatus.value.copy(isActive = false, hashrate = 0.0)
            }
            
            Result.success(start)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun refreshMiningStatus(): Result<MiningStatus> {
        return try {
            val wallet = _walletState.value ?: return Result.failure(Exception("No wallet found"))
            val response = apiService.getMiningStatus(wallet.address)
            _miningStatus.value = response
            Result.success(response)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Staking
    suspend fun startStaking(amount: Double): Result<Boolean> {
        return try {
            val wallet = _walletState.value ?: return Result.failure(Exception("No wallet found"))
            apiService.startStaking(
                mapOf(
                    "address" to wallet.address,
                    "amount" to amount
                )
            )
            
            // Update local staking info
            val currentStaking = _stakingInfo.value
            _stakingInfo.value = currentStaking.copy(
                stakedAmount = currentStaking.stakedAmount + amount
            )
            
            Result.success(true)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    // Utility Functions
    fun generateSeedPhrase(): List<String> {
        // BIP39 word list (simplified - in production use full list)
        val words = listOf(
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
            "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
            "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
            "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
            "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
            "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing"
        )
        
        return (1..12).map { words.random() }
    }
    
    private fun generateBitcoinAddress(wepoAddress: String): String {
        // Generate Bitcoin address from WEPO address (simplified)
        return "bc1q" + wepoAddress.takeLast(39)
    }
    
    fun getSeedPhrase(): String? {
        return _walletState.value?.let { wallet ->
            securityManager.loadSeedPhrase(wallet.address)
        }
    }
}