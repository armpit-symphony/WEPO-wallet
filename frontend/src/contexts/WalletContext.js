import React, { createContext, useContext, useState, useEffect } from 'react';
// Temporarily isolate each crypto import to identify the problematic one
// import * as bip39 from 'bip39';
// import CryptoJS from 'crypto-js';
// import { generateWepoAddress, generateBitcoinAddress, validateAddress } from '../utils/addressUtils';
// import SelfCustodialBitcoinWallet from '../utils/SelfCustodialBitcoinWallet';

const WalletContext = createContext();

export const useWallet = () => {
  const context = useContext(WalletContext);
  if (!context) {
    throw new Error('useWallet must be used within a WalletProvider');
  }
  return context;
};

export const WalletProvider = ({ children }) => {
  const [wallet, setWallet] = useState(null);
  const [balance, setBalance] = useState(0);
  const [btcBalance, setBtcBalance] = useState(0);
  const [transactions, setTransactions] = useState([]);
  const [btcTransactions, setBtcTransactions] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [posEnabled, setPosEnabled] = useState(false);
  const [masternodesEnabled, setMasternodesEnabled] = useState(false);
  const [showSeedPhrase, setShowSeedPhrase] = useState(false);
  
  // Self-custodial Bitcoin wallet state
  const [btcWallet, setBtcWallet] = useState(null);
  const [btcAddresses, setBtcAddresses] = useState([]);
  const [btcUtxos, setBtcUtxos] = useState([]);
  const [isBtcLoading, setIsBtcLoading] = useState(false);

  // Enable PoS after 18 months
  useEffect(() => {
    const timer = setTimeout(() => {
      setPosEnabled(true);
      setMasternodesEnabled(true);
    }, 100000); // For demo - in production this would be actual 18 months

    return () => clearTimeout(timer);
  }, []);

  const generateMnemonic = () => {
    // Temporarily disabled for isolation testing
    return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  };

  const createWallet = async (username, password, confirmPassword) => {
    if (password !== confirmPassword) {
      throw new Error('Passwords do not match');
    }

    try {
      const mnemonic = generateMnemonic();
      
      // Simplified wallet creation for isolation testing
      const walletData = {
        username,
        mnemonic,
        wepo: {
          address: "wepo1test123456789",
          privateKey: "test_private_key"
        },
        btc: {
          address: "1TestBitcoinAddress123",
          privateKey: "test_btc_private_key",
          publicKey: "test_btc_public_key",
          type: "legacy"
        },
        createdAt: new Date().toISOString(),
        version: '2.0'
      };

      // Store basic data
      localStorage.setItem('wepo_wallet_exists', 'true');
      localStorage.setItem('wepo_wallet_username', username);
      
      setWallet(walletData);
      return { mnemonic, address: walletData.wepo.address };
    } catch (error) {
      console.error('Wallet creation error:', error);
      throw new Error('Failed to create wallet: ' + error.message);
    }
  };

  const loginWallet = async (username, password) => {
    const storedUsername = localStorage.getItem('wepo_wallet_username');
    if (storedUsername !== username) {
      throw new Error('Invalid username');
    }

    try {
      // Simplified login for isolation testing
      const testWallet = {
        username,
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        wepo: {
          address: "wepo1test123456789",
          privateKey: "test_private_key"
        },
        btc: {
          address: "1TestBitcoinAddress123",
          privateKey: "test_btc_private_key",
          publicKey: "test_btc_public_key",
          type: "legacy"
        }
      };
      
      setWallet(testWallet);
      return testWallet;
    } catch (error) {
      console.error('Login error:', error);
      throw new Error('Invalid credentials or wallet data');
    }
  };

  const changePassword = async (currentPassword, newPassword, confirmNewPassword) => {
    if (newPassword !== confirmNewPassword) {
      throw new Error('New passwords do not match');
    }

    try {
      // Simplified password change for isolation testing
      console.log('Password change simulated');
      return true;
    } catch (error) {
      throw new Error('Invalid current password');
    }
  };

  // Remove old generateWepoAddress - now handled by addressUtils

  const loadWalletData = async (address) => {
    setIsLoading(true);
    try {
      // Check if we have a real backend connection
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      
      try {
        // Try to get real balance from blockchain
        const response = await fetch(`${backendUrl}/api/wallet/${address}`);
        if (response.ok) {
          const data = await response.json();
          setBalance(data.balance || 0);
          
          // Get real transaction history
          const txResponse = await fetch(`${backendUrl}/api/wallet/${address}/transactions`);
          if (txResponse.ok) {
            const txData = await txResponse.json();
            setTransactions(txData || []);
          }
        } else {
          // If blockchain not available, start with zero balance
          setBalance(0);
          setTransactions([]);
        }
      } catch (error) {
        console.log('Blockchain not connected, starting with zero balance');
        // Real cryptocurrency behavior - zero balance until actual transactions
        setBalance(0);
        setTransactions([]);
      }
      
    } catch (error) {
      console.error('Failed to load wallet data:', error);
      setBalance(0);
      setTransactions([]);
    } finally {
      setIsLoading(false);
    }
  };

  // ===== SELF-CUSTODIAL BITCOIN WALLET FUNCTIONS =====
  
  const initializeBitcoinWallet = async (seedPhrase) => {
    // Simplified for isolation testing
    return { success: true, mockInit: true };
  };

  const loadExistingBitcoinWallet = async (seedPhrase) => {
    // Simplified for isolation testing
    return { success: true, restored: false };
  };

  const loadBitcoinData = async (btcWalletInstance) => {
    // Simplified for isolation testing
    setBtcBalance(0.5);
    setBtcTransactions([]);
    setBtcUtxos([]);
  };

  const sendBitcoin = async (toAddress, amount, password) => {
    // Simplified for isolation testing
    return { success: true, txid: 'test_tx', fee: 0.0001 };
  };

  const getNewBitcoinAddress = () => {
    // Simplified for isolation testing
    return '1NewTestAddress123';
  };

  const getBitcoinBalance = () => {
    // Simplified for isolation testing
    return { confirmed: 0, unconfirmed: 0, total: 0 };
  };

  const exportBitcoinWalletInfo = () => {
    // Simplified for isolation testing
    return { addresses: [], balance: 0, utxoCount: 0, transactionCount: 0 };
  };

  const sendWepo = async (toAddress, amount, password) => {
    setIsLoading(true);
    try {
      // Simplified transaction for isolation testing
      const transaction = {
        id: Date.now().toString(),
        type: 'send',
        amount: parseFloat(amount),
        from: wallet.wepo.address,
        to: toAddress,
        timestamp: new Date().toISOString(),
        status: 'confirmed'
      };
      
      setTransactions(prev => [transaction, ...prev]);
      setBalance(prev => prev - parseFloat(amount));
      
      return transaction;
    } catch (error) {
      throw new Error('Transaction failed: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setWallet(null);
    setBalance(0);
    setTransactions([]);
    
    // Clear Bitcoin wallet data
    setBtcWallet(null);
    setBtcBalance(0);
    setBtcTransactions([]);
    setBtcAddresses([]);
    setBtcUtxos([]);
    
    sessionStorage.removeItem('wepo_session_active');
  };

  const value = {
    // State
    wallet,
    balance,
    btcBalance,
    transactions,
    btcTransactions,
    isLoading,
    posEnabled,
    masternodesEnabled,
    showSeedPhrase,
    setShowSeedPhrase,
    
    // Bitcoin wallet state
    btcWallet,
    btcAddresses,
    btcUtxos,
    isBtcLoading,
    
    // Actions
    generateMnemonic,
    createWallet,
    loginWallet,
    logout,
    sendWepo,
    loadWalletData,
    changePassword,
    setWallet,
    setBalance,
    setTransactions,
    
    // Bitcoin wallet actions
    sendBitcoin,
    getNewBitcoinAddress,
    getBitcoinBalance,
    exportBitcoinWalletInfo,
    initializeBitcoinWallet,
    loadExistingBitcoinWallet,
    
    // Legacy setters (keep for compatibility)
    setBtcBalance,
    setBtcTransactions
  };

  return (
    <WalletContext.Provider value={value}>
      {children}
    </WalletContext.Provider>
  );
};