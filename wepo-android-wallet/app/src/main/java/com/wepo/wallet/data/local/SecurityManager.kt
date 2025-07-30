package com.wepo.wallet.data.local

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.google.gson.Gson
import com.wepo.wallet.data.model.WalletData
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

@Singleton
class SecurityManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    
    private val keyAlias = "WepoWalletKey"
    private val walletPrefsName = "wepo_wallet_prefs"
    private val seedPhrasePrefix = "seed_phrase_"
    
    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    
    private val encryptedPrefs by lazy {
        EncryptedSharedPreferences.create(
            walletPrefsName,
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    private val gson = Gson()
    
    // Wallet Storage
    fun storeWallet(wallet: WalletData) {
        val walletJson = gson.toJson(wallet)
        encryptedPrefs.edit()
            .putString("wallet_data", walletJson)
            .apply()
    }
    
    fun loadWallet(): WalletData? {
        val walletJson = encryptedPrefs.getString("wallet_data", null)
        return walletJson?.let { 
            try {
                gson.fromJson(it, WalletData::class.java)
            } catch (e: Exception) {
                null
            }
        }
    }
    
    fun deleteWallet(address: String) {
        encryptedPrefs.edit()
            .remove("wallet_data")
            .remove("${seedPhrasePrefix}$address")
            .apply()
    }
    
    // Seed Phrase Storage with Enhanced Security
    fun storeSeedPhrase(seedPhrase: String, address: String) {
        try {
            generateSecretKey()
            val encryptedData = encryptData(seedPhrase.toByteArray())
            
            encryptedPrefs.edit()
                .putString("${seedPhrasePrefix}$address", encryptedData)
                .apply()
                
        } catch (e: Exception) {
            throw SecurityException("Failed to store seed phrase securely", e)
        }
    }
    
    fun loadSeedPhrase(address: String): String? {
        return try {
            val encryptedData = encryptedPrefs.getString("${seedPhrasePrefix}$address", null)
            encryptedData?.let { 
                val decryptedBytes = decryptData(it)
                String(decryptedBytes)
            }
        } catch (e: Exception) {
            null
        }
    }
    
    // Biometric Authentication
    suspend fun authenticateWithBiometrics(
        activity: FragmentActivity,
        title: String,
        subtitle: String
    ): Boolean = suspendCoroutine { continuation ->
        
        val biometricManager = BiometricManager.from(context)
        
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                // Biometrics available
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                continuation.resumeWithException(SecurityException("No biometric hardware available"))
                return@suspendCoroutine
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                continuation.resumeWithException(SecurityException("Biometric hardware unavailable"))
                return@suspendCoroutine
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                continuation.resumeWithException(SecurityException("No biometrics enrolled"))
                return@suspendCoroutine
            }
        }
        
        val executor: Executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                continuation.resumeWithException(SecurityException("Authentication error: $errString"))
            }
            
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                continuation.resume(true)
            }
            
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                continuation.resumeWithException(SecurityException("Authentication failed"))
            }
        })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .build()
            
        biometricPrompt.authenticate(promptInfo)
    }
    
    // Address Validation
    fun validateWepoAddress(address: String): Boolean {
        return address.startsWith("wepo") && address.length == 40
    }
    
    fun validateBitcoinAddress(address: String): Boolean {
        val validPrefixes = listOf("1", "3", "bc1")
        val hasValidPrefix = validPrefixes.any { address.startsWith(it) }
        val validLength = address.length in 26..62
        return hasValidPrefix && validLength
    }
    
    // Input Sanitization
    fun sanitizeInput(input: String): String {
        return input.filter { it.isLetterOrDigit() || it in " .-_@" }
    }
    
    fun validateTransactionAmount(amount: String): Double? {
        return try {
            val doubleValue = amount.toDouble()
            if (doubleValue > 0 && doubleValue <= 1_000_000) {
                // Limit to 8 decimal places
                val multiplier = 100_000_000.0
                (doubleValue * multiplier).toLong() / multiplier
            } else null
        } catch (e: NumberFormatException) {
            null
        }
    }
    
    // Private Encryption/Decryption Methods
    private fun generateSecretKey() {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false) // Can be changed to true for extra security
            .build()
            
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }
    
    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        return keyStore.getKey(keyAlias, null) as SecretKey
    }
    
    private fun encryptData(data: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        
        val iv = cipher.iv
        val encryptedData = cipher.doFinal(data)
        
        // Combine IV and encrypted data
        val combined = iv + encryptedData
        return android.util.Base64.encodeToString(combined, android.util.Base64.DEFAULT)
    }
    
    private fun decryptData(encryptedString: String): ByteArray {
        val combined = android.util.Base64.decode(encryptedString, android.util.Base64.DEFAULT)
        
        val iv = combined.sliceArray(0..11) // GCM IV is 12 bytes
        val encryptedData = combined.sliceArray(12 until combined.size)
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)
        
        return cipher.doFinal(encryptedData)
    }
    
    // Utility Methods
    fun isBiometricAvailable(): Boolean {
        val biometricManager = BiometricManager.from(context)
        return biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS
    }
    
    fun clearAllData() {
        encryptedPrefs.edit().clear().apply()
        
        // Also clear Android Keystore
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            keyStore.deleteEntry(keyAlias)
        } catch (e: Exception) {
            // Handle keystore cleanup error
        }
    }
}