package com.wepo.wallet.data.remote

import com.wepo.wallet.data.model.*
import retrofit2.http.*

interface WepoApiService {
    
    // Wallet Management
    @POST("/api/wallet/create")
    suspend fun createWallet(@Body request: Map<String, String>): CreateWalletResponse
    
    @POST("/api/wallet/import")
    suspend fun importWallet(@Body request: Map<String, String>): CreateWalletResponse
    
    @GET("/api/wallet/{address}")
    suspend fun getWallet(@Path("address") address: String): WalletData
    
    // Balance and Transactions
    @GET("/api/balance/{address}")
    suspend fun getBalance(@Path("address") address: String): BalanceResponse
    
    @GET("/api/transactions/{address}")
    suspend fun getTransactions(@Path("address") address: String): TransactionsResponse
    
    @POST("/api/transactions/send")
    suspend fun sendTransaction(@Body request: Map<String, Any>): Transaction
    
    // Bitcoin Integration
    @POST("/api/bitcoin/wallet/init")
    suspend fun initializeBitcoinWallet(@Body request: Map<String, String>): BitcoinBalanceResponse
    
    @GET("/api/bitcoin/balance/{address}")
    suspend fun getBitcoinBalance(@Path("address") address: String): BitcoinBalanceResponse
    
    @POST("/api/bitcoin/wallet/sync")
    suspend fun syncBitcoinWallet(@Body request: Map<String, String>): BitcoinBalanceResponse
    
    // Network Status
    @GET("/api/network/status")
    suspend fun getNetworkStatus(): NetworkStatusResponse
    
    // Mining
    @POST("/api/mining/start")
    suspend fun startMining(@Body request: Map<String, String>): APIResponse
    
    @POST("/api/mining/stop")
    suspend fun stopMining(@Body request: Map<String, String>): APIResponse
    
    @GET("/api/mining/status/{address}")
    suspend fun getMiningStatus(@Path("address") address: String): MiningStatus
    
    // Staking
    @POST("/api/staking/stake")
    suspend fun startStaking(@Body request: Map<String, Any>): APIResponse
    
    @POST("/api/staking/unstake")
    suspend fun unstake(@Body request: Map<String, Any>): APIResponse
    
    @GET("/api/staking/info/{address}")
    suspend fun getStakingInfo(@Path("address") address: String): StakingInfo
    
    // Quantum Vault
    @POST("/api/vault/create")
    suspend fun createVault(@Body request: Map<String, Any>): VaultResponse
    
    @GET("/api/vault/wallet/{address}")
    suspend fun getVaults(@Path("address") address: String): VaultsResponse
}

@kotlinx.serialization.Serializable
data class APIResponse(
    val success: Boolean,
    val message: String
)

@kotlinx.serialization.Serializable
data class VaultResponse(
    val vaultId: String,
    val vaultType: String,
    val status: String,
    val message: String
)

@kotlinx.serialization.Serializable
data class VaultsResponse(
    val vaults: List<VaultInfo>
)