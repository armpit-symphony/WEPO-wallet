package com.wepo.wallet.data.model

import kotlinx.serialization.Serializable
import java.util.Date

@Serializable
data class WalletData(
    val id: String,
    val username: String,
    val address: String,
    val publicKey: String,
    val createdAt: Long = System.currentTimeMillis()
) {
    fun getCreatedDate(): Date = Date(createdAt)
}

@Serializable
data class Transaction(
    val id: String,
    val type: TransactionType,
    val amount: Double,
    val fromAddress: String,
    val toAddress: String,
    val timestamp: Long,
    val status: TransactionStatus,
    val txHash: String,
    val isPrivate: Boolean = false
)

@Serializable
enum class TransactionType {
    SENT, RECEIVED
}

@Serializable
enum class TransactionStatus {
    PENDING, CONFIRMED, FAILED
}

@Serializable
data class BitcoinWallet(
    val address: String,
    val publicKey: String,
    val balance: Double = 0.0
)

@Serializable
data class VaultInfo(
    val id: String,
    val vaultType: String,
    val status: String,
    val balance: Double,
    val createdAt: Long
)

@Serializable
data class NetworkStatus(
    val isConnected: Boolean,
    val currentBlock: Int,
    val peerCount: Int,
    val networkHash: String
)

@Serializable
data class MiningStatus(
    val isActive: Boolean,
    val hashrate: Double,
    val blocksFound: Int,
    val earnings: Double
)

@Serializable
data class StakingInfo(
    val stakedAmount: Double,
    val rewards: Double,
    val apy: Double,
    val lockPeriod: Int
)

// API Response Models
@Serializable
data class CreateWalletResponse(
    val id: String,
    val address: String,
    val publicKey: String,
    val message: String
)

@Serializable
data class BalanceResponse(
    val balance: Double,
    val stakingBalance: Double,
    val stakingRewards: Double
)

@Serializable
data class TransactionsResponse(
    val transactions: List<Transaction>
)

@Serializable
data class BitcoinBalanceResponse(
    val balance: Double,
    val address: String
)

@Serializable
data class NetworkStatusResponse(
    val isConnected: Boolean,
    val currentBlock: Int,
    val peerCount: Int,
    val networkHash: String
)

@Serializable
data class APIErrorResponse(
    val detail: String
)