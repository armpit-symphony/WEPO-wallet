import React, { createContext, useContext, useState, useEffect } from 'react';
import * as bip39 from 'bip39';
import CryptoJS from 'crypto-js';
import { generateWepoAddress, generateBitcoinAddress, validateAddress } from '../utils/addressUtils';

const UnifiedWalletContext = createContext();

export const useUnifiedWallet = () => {
  const context = useContext(UnifiedWalletContext);
  if (!context) {
    throw new Error('useUnifiedWallet must be used within an UnifiedWalletProvider');
  }
  return context;
};

export const UnifiedWalletProvider = ({ children }) => {
  // Wallet state
  const [wallet, setWallet] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  
  // Balance states
  const [wepoBalance, setWepoBalance] = useState(0);
  const [btcBalance, setBtcBalance] = useState(0);
  
  // Transaction states
  const [wepoTransactions, setWepoTransactions] = useState([]);
  const [btcTransactions, setBtcTransactions] = useState([]);
  
  // UI states
  const [showSeedPhrase, setShowSeedPhrase] = useState(false);
  const [seedConfirmed, setSeedConfirmed] = useState(false);

  // Create new unified wallet (BTC + WEPO from same seed)
  const createWallet = async (username, password) => {
    try {
      setIsLoading(true);
      
      // Generate mnemonic seed phrase
      const mnemonic = bip39.generateMnemonic();
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      
      // Generate WEPO address (regular type)
      const wepoAddress = generateWepoAddress(seed, 'regular');
      
      // Generate Bitcoin address (legacy type for better compatibility)
      const btcWallet = generateBitcoinAddress(seed, 'legacy');
      
      // Create unified wallet object
      const newWallet = {
        username,
        mnemonic,
        seed: seed.toString('hex'),
        wepo: {
          address: wepoAddress,
          privateKey: CryptoJS.SHA256(seed.toString('hex')).toString()
        },
        btc: {
          address: btcWallet.address,
          privateKey: btcWallet.privateKey,
          publicKey: btcWallet.publicKey,
          type: btcWallet.type
        },
        createdAt: new Date().toISOString(),
        version: '2.0' // Unified wallet version
      };
      
      // Encrypt and store wallet
      const encryptedWallet = CryptoJS.AES.encrypt(
        JSON.stringify(newWallet), 
        password
      ).toString();
      
      localStorage.setItem(`wepo_unified_wallet_${username}`, encryptedWallet);
      localStorage.setItem('wepo_current_user', username);
      
      // Set wallet state
      setWallet(newWallet);
      setShowSeedPhrase(true);
      
      // Load initial balances
      await loadWalletBalances(newWallet);
      
      return newWallet;
    } catch (error) {
      console.error('Wallet creation error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  // Login to existing wallet
  const loginWallet = async (username, password) => {
    try {
      setIsLoading(true);
      
      const encryptedWallet = localStorage.getItem(`wepo_unified_wallet_${username}`);
      if (!encryptedWallet) {
        throw new Error('Wallet not found');
      }
      
      // Decrypt wallet
      const decryptedBytes = CryptoJS.AES.decrypt(encryptedWallet, password);
      const decryptedWallet = JSON.parse(decryptedBytes.toString(CryptoJS.enc.Utf8));
      
      // Verify wallet structure
      if (!decryptedWallet.wepo || !decryptedWallet.btc) {
        throw new Error('Invalid wallet format');
      }
      
      // Set wallet state
      setWallet(decryptedWallet);
      localStorage.setItem('wepo_current_user', username);
      
      // Load balances and transactions
      await loadWalletBalances(decryptedWallet);
      
      return decryptedWallet;
    } catch (error) {
      console.error('Wallet login error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  // Load wallet balances from blockchain
  const loadWalletBalances = async (walletData) => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      
      // Load WEPO balance
      const wepoResponse = await fetch(`${backendUrl}/api/wallet/balance/${walletData.wepo.address}`);
      if (wepoResponse.ok) {
        const wepoData = await wepoResponse.json();
        setWepoBalance(wepoData.balance || 0);
      }
      
      // Load BTC balance (placeholder - will be implemented with real BTC integration)
      // For now, use simulated balance
      setBtcBalance(0.00000000);
      
      // Load transaction histories
      await loadTransactionHistories(walletData);
      
    } catch (error) {
      console.error('Balance loading error:', error);
      // Set default values on error
      setWepoBalance(0);
      setBtcBalance(0);
    }
  };

  // Load transaction histories
  const loadTransactionHistories = async (walletData) => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      
      // Load WEPO transactions
      const wepoTxResponse = await fetch(`${backendUrl}/api/wallet/transactions/${walletData.wepo.address}`);
      if (wepoTxResponse.ok) {
        const wepoTxData = await wepoTxResponse.json();
        setWepoTransactions(wepoTxData.transactions || []);
      }
      
      // Load BTC transactions (placeholder)
      setBtcTransactions([]);
      
    } catch (error) {
      console.error('Transaction history loading error:', error);
      setWepoTransactions([]);
      setBtcTransactions([]);
    }
  };

  // Send WEPO transaction
  const sendWepo = async (toAddress, amount, memo = '') => {
    try {
      setIsLoading(true);
      
      if (!wallet) throw new Error('No wallet loaded');
      
      // Validate address
      const addressValidation = validateAddress(toAddress);
      if (!addressValidation.valid || (addressValidation.type !== 'regular' && addressValidation.type !== 'quantum')) {
        throw new Error('Invalid WEPO address');
      }
      
      // Validate amount
      const sendAmount = parseFloat(amount);
      if (sendAmount <= 0 || sendAmount > wepoBalance) {
        throw new Error('Invalid amount');
      }
      
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/wallet/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from_address: wallet.wepo.address,
          to_address: toAddress,
          amount: sendAmount,
          memo: memo,
          private_key: wallet.wepo.privateKey
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Transaction failed');
      }
      
      const result = await response.json();
      
      // Reload balances and transactions
      await loadWalletBalances(wallet);
      
      return result;
    } catch (error) {
      console.error('WEPO send error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  // Send BTC transaction (placeholder - will be implemented)
  const sendBtc = async (toAddress, amount, feeRate = 'medium') => {
    try {
      setIsLoading(true);
      
      if (!wallet) throw new Error('No wallet loaded');
      
      // Validate BTC address
      const addressValidation = validateAddress(toAddress);
      if (!addressValidation.valid || !addressValidation.type.startsWith('bitcoin')) {
        throw new Error('Invalid Bitcoin address');
      }
      
      // Validate amount
      const sendAmount = parseFloat(amount);
      if (sendAmount <= 0 || sendAmount > btcBalance) {
        throw new Error('Invalid amount');
      }
      
      // TODO: Implement actual BTC transaction broadcasting
      // For now, this is a placeholder
      throw new Error('BTC sending will be implemented with full Bitcoin node integration');
      
    } catch (error) {
      console.error('BTC send error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  // Internal BTC ↔ WEPO swap
  const swapCurrencies = async (fromCurrency, toCurrency, amount) => {
    try {
      setIsLoading(true);
      
      if (!wallet) throw new Error('No wallet loaded');
      
      const swapAmount = parseFloat(amount);
      if (swapAmount <= 0) {
        throw new Error('Invalid swap amount');
      }
      
      // Get current exchange rate
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const rateResponse = await fetch(`${backendUrl}/api/swap/rate`);
      const rateData = await rateResponse.json();
      const exchangeRate = rateData.btc_to_wepo || 1.007;
      
      let outputAmount;
      if (fromCurrency === 'BTC' && toCurrency === 'WEPO') {
        // BTC to WEPO
        if (swapAmount > btcBalance) {
          throw new Error('Insufficient BTC balance');
        }
        outputAmount = swapAmount * exchangeRate;
      } else if (fromCurrency === 'WEPO' && toCurrency === 'BTC') {
        // WEPO to BTC
        if (swapAmount > wepoBalance) {
          throw new Error('Insufficient WEPO balance');
        }
        outputAmount = swapAmount / exchangeRate;
      } else {
        throw new Error('Invalid swap pair');
      }
      
      // Execute swap through backend
      const swapResponse = await fetch(`${backendUrl}/api/swap/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          wallet_address: wallet.wepo.address,
          from_currency: fromCurrency,
          to_currency: toCurrency,
          from_amount: swapAmount,
          to_amount: outputAmount,
          exchange_rate: exchangeRate
        })
      });
      
      if (!swapResponse.ok) {
        const errorData = await swapResponse.json();
        throw new Error(errorData.detail || 'Swap failed');
      }
      
      const swapResult = await swapResponse.json();
      
      // Update balances locally
      if (fromCurrency === 'BTC') {
        setBtcBalance(prev => prev - swapAmount);
        setWepoBalance(prev => prev + outputAmount);
      } else {
        setWepoBalance(prev => prev - swapAmount);
        setBtcBalance(prev => prev + outputAmount);
      }
      
      // Reload from backend
      await loadWalletBalances(wallet);
      
      return swapResult;
    } catch (error) {
      console.error('Swap error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  // Logout wallet
  const logoutWallet = () => {
    setWallet(null);
    setWepoBalance(0);
    setBtcBalance(0);
    setWepoTransactions([]);
    setBtcTransactions([]);
    setShowSeedPhrase(false);
    setSeedConfirmed(false);
    localStorage.removeItem('wepo_current_user');
  };

  // Auto-login on app start
  useEffect(() => {
    const currentUser = localStorage.getItem('wepo_current_user');
    if (currentUser && !wallet) {
      // Try to restore session if available
      const sessionWallet = sessionStorage.getItem('wepo_unified_session');
      if (sessionWallet) {
        try {
          const parsedWallet = JSON.parse(sessionWallet);
          setWallet(parsedWallet);
          loadWalletBalances(parsedWallet);
        } catch (error) {
          console.error('Session restore error:', error);
        }
      }
    }
  }, [wallet]);

  const value = {
    // Wallet state
    wallet,
    isLoading,
    
    // Balances
    wepoBalance,
    btcBalance,
    
    // Transactions
    wepoTransactions,
    btcTransactions,
    
    // UI state
    showSeedPhrase,
    setShowSeedPhrase,
    seedConfirmed,
    setSeedConfirmed,
    
    // Actions
    createWallet,
    loginWallet,
    logoutWallet,
    sendWepo,
    sendBtc,
    swapCurrencies,
    loadWalletBalances,
    
    // Utilities
    validateAddress
  };

  return (
    <UnifiedWalletContext.Provider value={value}>
      {children}
    </UnifiedWalletContext.Provider>
  );
};

export default UnifiedWalletContext;