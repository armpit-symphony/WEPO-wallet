import React, { createContext, useContext, useState, useEffect } from 'react';
import * as bip39 from 'bip39';
import CryptoJS from 'crypto-js';

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
  const [isLoading, setIsLoading] = useState(false);
  const [transactions, setTransactions] = useState([]);
  
  // WEPO specific state
  const [wepoLaunched, setWepoLaunched] = useState(false);
  const [posEnabled, setPosEnabled] = useState(false);
  const [masternodesEnabled, setMasternodesEnabled] = useState(false);

  useEffect(() => {
    // Check if 18 months have passed since first PoW block (simulated for demo)
    // In real implementation, this would check the blockchain
    const launchDate = localStorage.getItem('wepo_launch_date');
    if (launchDate) {
      const eighteenMonthsLater = new Date(launchDate);
      eighteenMonthsLater.setMonth(eighteenMonthsLater.getMonth() + 18);
      
      if (new Date() > eighteenMonthsLater) {
        setPosEnabled(true);
        setMasternodesEnabled(true);
      }
    }
  }, []);

  const generateMnemonic = () => {
    try {
      return bip39.generateMnemonic(128); // 12 words for better UX
    } catch (error) {
      console.error('BIP39 generation failed, using fallback:', error);
      // Fallback: generate a simple seed phrase for demo
      const words = [
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
        'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act'
      ];
      const mnemonic = [];
      for (let i = 0; i < 12; i++) {
        mnemonic.push(words[Math.floor(Math.random() * words.length)]);
      }
      return mnemonic.join(' ');
    }
  };

  const createWallet = async (username, password, confirmPassword) => {
    if (password !== confirmPassword) {
      throw new Error('Passwords do not match');
    }

    try {
      const mnemonic = generateMnemonic();
      const seed = bip39.mnemonicToSeedSync(mnemonic);
      
      // Encrypt the mnemonic with the password
      const encryptedMnemonic = CryptoJS.AES.encrypt(mnemonic, password).toString();
      
      // Create wallet object
      const walletData = {
        username,
        address: generateWepoAddress(seed),
        encryptedMnemonic,
        createdAt: new Date().toISOString(),
        balance: 0
      };

      // Store wallet data (encrypted)
      const encryptedWallet = CryptoJS.AES.encrypt(JSON.stringify(walletData), password).toString();
      localStorage.setItem('wepo_wallet', encryptedWallet);
      localStorage.setItem('wepo_wallet_exists', 'true');
      localStorage.setItem('wepo_wallet_username', username);
      
      // Set launch date for demo purposes
      if (!localStorage.getItem('wepo_launch_date')) {
        localStorage.setItem('wepo_launch_date', new Date().toISOString());
      }

      setWallet(walletData);
      return { mnemonic, address: walletData.address };
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

    const walletData = localStorage.getItem('wepo_wallet');
    if (!walletData) {
      throw new Error('Wallet not found');
    }

    try {
      const parsedWallet = JSON.parse(walletData);
      setWallet(parsedWallet);
      sessionStorage.setItem('wepo_session_active', 'true');
      sessionStorage.setItem('wepo_current_wallet', walletData);
      
      // Load balance and transactions
      await loadWalletData(parsedWallet.address);
      
      return parsedWallet;
    } catch (error) {
      throw new Error('Invalid wallet data');
    }
  };

  const changePassword = async (currentPassword, newPassword, confirmNewPassword) => {
    if (newPassword !== confirmNewPassword) {
      throw new Error('New passwords do not match');
    }

    const encryptedWallet = localStorage.getItem('wepo_wallet');
    if (!encryptedWallet) {
      throw new Error('Wallet not found');
    }

    try {
      // Decrypt with current password
      const decryptedWallet = CryptoJS.AES.decrypt(encryptedWallet, currentPassword).toString(CryptoJS.enc.Utf8);
      const walletData = JSON.parse(decryptedWallet);
      
      // Re-encrypt with new password
      const newEncryptedWallet = CryptoJS.AES.encrypt(JSON.stringify(walletData), newPassword).toString();
      localStorage.setItem('wepo_wallet', newEncryptedWallet);
      
      return true;
    } catch (error) {
      throw new Error('Invalid current password');
    }
  };

  const generateWepoAddress = (seed) => {
    // Generate WEPO address from seed
    // In real implementation, this would use WEPO's address format
    const hash = CryptoJS.SHA256(seed.toString('hex')).toString();
    return `wepo1${hash.substring(0, 32)}`;
  };

  const loadWalletData = async (address) => {
    setIsLoading(true);
    try {
      // Simulate API call to get balance and transactions
      // In real implementation, this would call the WEPO blockchain API
      const mockBalance = 1000.5; // Mock balance
      const mockTransactions = [
        {
          id: '1',
          type: 'receive',
          amount: 100,
          from: 'wepo1abc...def',
          to: address,
          timestamp: new Date().toISOString(),
          status: 'confirmed'
        },
        {
          id: '2',
          type: 'send',
          amount: 50,
          from: address,
          to: 'wepo1xyz...123',
          timestamp: new Date(Date.now() - 86400000).toISOString(),
          status: 'confirmed'
        }
      ];
      
      setBalance(mockBalance);
      setTransactions(mockTransactions);
    } catch (error) {
      console.error('Failed to load wallet data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const sendWepo = async (toAddress, amount, password) => {
    setIsLoading(true);
    try {
      // Verify password
      const encryptedWallet = localStorage.getItem('wepo_wallet');
      const decryptedWallet = CryptoJS.AES.decrypt(encryptedWallet, password).toString(CryptoJS.enc.Utf8);
      JSON.parse(decryptedWallet); // This will throw if password is wrong
      
      // Create transaction (simulated)
      const transaction = {
        id: Date.now().toString(),
        type: 'send',
        amount: parseFloat(amount),
        from: wallet.address,
        to: toAddress,
        timestamp: new Date().toISOString(),
        status: 'pending'
      };
      
      // Add to transactions
      setTransactions(prev => [transaction, ...prev]);
      
      // Update balance
      setBalance(prev => prev - parseFloat(amount));
      
      // Simulate confirmation after 3 seconds
      setTimeout(() => {
        setTransactions(prev => 
          prev.map(tx => 
            tx.id === transaction.id 
              ? { ...tx, status: 'confirmed' }
              : tx
          )
        );
      }, 3000);
      
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
    sessionStorage.removeItem('wepo_session_active');
  };

  const value = {
    wallet,
    balance,
    isLoading,
    transactions,
    posEnabled,
    masternodesEnabled,
    wepoLaunched,
    generateMnemonic,
    createWallet,
    loginWallet,
    changePassword,
    sendWepo,
    logout,
    loadWalletData
  };

  return (
    <WalletContext.Provider value={value}>
      {children}
    </WalletContext.Provider>
  );
};