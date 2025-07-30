package com.wepo.wallet.presentation.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.wepo.wallet.data.model.*
import com.wepo.wallet.data.repository.WalletRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class WalletViewModel @Inject constructor(
    private val walletRepository: WalletRepository
) : ViewModel() {
    
    // Wallet State
    val walletState = walletRepository.walletState.asStateFlow()
    val balance = walletRepository.balance.asStateFlow()
    val bitcoinBalance = walletRepository.bitcoinBalance.asStateFlow()
    val transactions = walletRepository.transactions.asStateFlow()
    val networkStatus = walletRepository.networkStatus.asStateFlow()
    val stakingInfo = walletRepository.stakingInfo.asStateFlow()
    val miningStatus = walletRepository.miningStatus.asStateFlow()
    
    // UI State
    private val _uiState = MutableStateFlow(WalletUiState())
    val uiState = _uiState.asStateFlow()
    
    // Loading states
    private val _isLoading = MutableStateFlow(false)
    val isLoading = _isLoading.asStateFlow()
    
    private val _error = MutableStateFlow<String?>(null)
    val error = _error.asStateFlow()
    
    // Computed properties
    val hasWallet = walletState.map { it != null }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = false
    )
    
    val isConnected = networkStatus.map { it.isConnected }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = false
    )
    
    init {
        loadWallet()
        startPeriodicRefresh()
    }
    
    // Wallet Management
    fun loadWallet() {
        walletRepository.loadWallet()
        if (walletState.value != null) {
            refreshAllData()
        }
    }
    
    fun createWallet(username: String, password: String, seedPhrase: String) {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null
            
            walletRepository.createWallet(username, password, seedPhrase)
                .onSuccess {
                    _uiState.value = _uiState.value.copy(isWalletSetupComplete = true)
                    refreshAllData()
                }
                .onFailure { exception ->
                    _error.value = exception.message
                }
            
            _isLoading.value = false
        }
    }
    
    fun importWallet(username: String, password: String, seedPhrase: String) {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null
            
            walletRepository.importWallet(username, password, seedPhrase)
                .onSuccess {
                    _uiState.value = _uiState.value.copy(isWalletSetupComplete = true)
                    refreshAllData()
                }
                .onFailure { exception ->
                    _error.value = exception.message
                }
            
            _isLoading.value = false
        }
    }
    
    fun logout() {
        walletRepository.logout()
        _uiState.value = WalletUiState()
    }
    
    fun deleteWallet() {
        walletRepository.deleteWallet()
        _uiState.value = WalletUiState()
    }
    
    // Transaction Operations
    fun sendTransaction(toAddress: String, amount: Double, isPrivate: Boolean) {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null
            
            walletRepository.sendTransaction(toAddress, amount, isPrivate)
                .onSuccess {
                    _uiState.value = _uiState.value.copy(lastTransactionSuccess = true)
                    refreshBalance()
                    refreshTransactions()
                }
                .onFailure { exception ->
                    _error.value = exception.message
                }
            
            _isLoading.value = false
        }
    }
    
    fun getReceiveAddress(): String {
        return walletState.value?.address ?: ""
    }
    
    // Data Refresh
    fun refreshAllData() {
        viewModelScope.launch {
            refreshBalance()
            refreshTransactions()
            refreshNetworkStatus()
            refreshBitcoinBalance()
        }
    }
    
    private fun refreshBalance() {
        viewModelScope.launch {
            walletRepository.refreshBalance()
                .onFailure { exception ->
                    _error.value = exception.message
                }
        }
    }
    
    private fun refreshTransactions() {
        viewModelScope.launch {
            walletRepository.refreshTransactions()
                .onFailure { exception ->
                    _error.value = exception.message
                }
        }
    }
    
    private fun refreshNetworkStatus() {
        viewModelScope.launch {
            walletRepository.refreshNetworkStatus()
                .onFailure { exception ->
                    _error.value = exception.message
                }
        }
    }
    
    private fun refreshBitcoinBalance() {
        viewModelScope.launch {
            walletRepository.refreshBitcoinBalance()
                .onFailure { exception ->
                    _error.value = exception.message
                }
        }
    }
    
    // Mining Operations
    fun toggleMining() {
        viewModelScope.launch {
            val currentlyMining = miningStatus.value.isActive
            walletRepository.toggleMining(!currentlyMining)
                .onFailure { exception ->
                    _error.value = exception.message
                }
        }
    }
    
    fun refreshMiningStatus() {
        viewModelScope.launch {
            walletRepository.refreshMiningStatus()
                .onFailure { exception ->
                    _error.value = exception.message
                }
        }
    }
    
    // Staking Operations
    fun startStaking(amount: Double) {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null
            
            walletRepository.startStaking(amount)
                .onSuccess {
                    refreshBalance()
                }
                .onFailure { exception ->
                    _error.value = exception.message
                }
            
            _isLoading.value = false
        }
    }
    
    // Utility Functions
    fun generateSeedPhrase(): List<String> {
        return walletRepository.generateSeedPhrase()
    }
    
    fun getSeedPhrase(): String? {
        return walletRepository.getSeedPhrase()
    }
    
    fun clearError() {
        _error.value = null
    }
    
    fun clearTransactionSuccess() {
        _uiState.value = _uiState.value.copy(lastTransactionSuccess = false)
    }
    
    // Private Methods
    private fun startPeriodicRefresh() {
        viewModelScope.launch {
            while (true) {
                kotlinx.coroutines.delay(30000) // 30 seconds
                if (walletState.value != null) {
                    refreshAllData()
                }
            }
        }
    }
}

data class WalletUiState(
    val isWalletSetupComplete: Boolean = false,
    val lastTransactionSuccess: Boolean = false,
    val selectedTab: Int = 0,
    val isPrivateMode: Boolean = false
)