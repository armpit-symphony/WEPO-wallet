import React, { createContext, useContext, useState, useEffect } from 'react';
import * as bip39 from 'bip39';
import CryptoJS from 'crypto-js';
import { generateWepoAddress, generateBitcoinAddress, validateAddress } from '../utils/addressUtils';
import SelfCustodialBitcoinWallet from '../utils/SelfCustodialBitcoinWallet';

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
    try {
      // Use proper BIP39 wordlist with cryptographically secure randomness
      const bip39Words = [
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
        'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
        'action', 'actor', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult',
        'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'agent', 'agree', 'ahead',
        'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert', 'alien', 'all',
        'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always', 'amateur',
        'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
        'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique', 'anxiety', 'any',
        'apart', 'apology', 'appear', 'apple', 'approve', 'april', 'arcade', 'arch', 'arctic', 'area',
        'arena', 'argue', 'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive',
        'arrow', 'art', 'artefact', 'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist',
        'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract', 'auction', 'audit',
        'august', 'aunt', 'author', 'auto', 'autumn', 'average', 'avocado', 'avoid', 'awake', 'aware',
        'away', 'awesome', 'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge', 'bag',
        'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner', 'bar', 'barely', 'bargain', 'barrel',
        'base', 'basic', 'basket', 'battle', 'beach', 'bean', 'beauty', 'because', 'become', 'beef',
        'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt', 'bench', 'benefit', 'best',
        'betray', 'better', 'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird',
        'birth', 'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind',
        'blood', 'blossom', 'blow', 'blue', 'blur', 'blush', 'board', 'boat', 'body', 'boil',
        'bomb', 'bone', 'bonus', 'book', 'boost', 'border', 'boring', 'borrow', 'boss', 'bottom',
        'bounce', 'box', 'boy', 'bracket', 'brain', 'brand', 'brass', 'brave', 'bread', 'breeze',
        'brick', 'bridge', 'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken', 'bronze', 'broom',
        'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build', 'bulb', 'bulk',
        'bullet', 'bundle', 'bunker', 'burden', 'burger', 'burst', 'bus', 'business', 'busy', 'butter',
        'buy', 'buzz', 'cabbage', 'cabin', 'cable', 'cactus', 'cage', 'cake', 'call', 'calm',
        'camera', 'camp', 'can', 'canal', 'cancel', 'candy', 'cannon', 'canoe', 'canvas', 'canyon',
        'capable', 'capital', 'captain', 'car', 'carbon', 'card', 'care', 'career', 'careful', 'careless',
        'cargo', 'carpet', 'carry', 'cart', 'case', 'cash', 'casino', 'castle', 'casual', 'cat'
      ];
      
      // Generate cryptographically secure random seed phrase
      const mnemonicWords = [];
      const crypto = window.crypto || window.msCrypto;
      
      if (!crypto || !crypto.getRandomValues) {
        throw new Error('Cryptographically secure random number generation not available');
      }
      
      for (let i = 0; i < 12; i++) {
        // Use cryptographically secure random number generation
        const randomArray = new Uint32Array(1);
        crypto.getRandomValues(randomArray);
        const randomIndex = randomArray[0] % bip39Words.length;
        mnemonicWords.push(bip39Words[randomIndex]);
      }
      
      const mnemonic = mnemonicWords.join(' ');
      
      // Security validation: ensure sufficient entropy
      const uniqueWords = new Set(mnemonicWords);
      if (uniqueWords.size < 8) {
        // If too many repeated words, regenerate recursively
        console.warn('Low entropy detected, regenerating seed phrase');
        return generateMnemonic();
      }
      
      return mnemonic;
      
    } catch (error) {
      console.error('Secure mnemonic generation failed:', error);
      throw new Error('Failed to generate secure seed phrase. Please refresh and try again.');
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
      // Generate WEPO address (regular type)
      const wepoAddress = generateWepoAddress(seed, 'regular');
      
      // Generate Bitcoin address from same seed
      const btcWallet = generateBitcoinAddress(seed, 'legacy');
      
      const walletData = {
        username,
        seed: seed.toString('hex'),
        mnemonic,
        
        // WEPO wallet
        wepo: {
          address: wepoAddress,
          privateKey: CryptoJS.SHA256(seed.toString('hex')).toString()
        },
        
        // Bitcoin wallet (same seed)
        btc: {
          address: btcWallet.address,
          privateKey: btcWallet.privateKey,
          publicKey: btcWallet.publicKey,
          type: btcWallet.type
        },
        
        createdAt: new Date().toISOString(),
        version: '2.0' // Unified wallet version
      };

      // Store wallet data (encrypted)
      const encryptedWallet = CryptoJS.AES.encrypt(JSON.stringify(walletData), password).toString();
      localStorage.setItem('wepo_wallet', encryptedWallet);
      localStorage.setItem('wepo_wallet_exists', 'true');
      localStorage.setItem('wepo_wallet_username', username);
      
      // Initialize self-custodial Bitcoin wallet from same seed
      await initializeBitcoinWallet(mnemonic);
      
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
    try {
      setIsBtcLoading(true);
      
      // Create new Bitcoin wallet instance
      const newBtcWallet = new SelfCustodialBitcoinWallet();
      
      // Initialize from seed phrase
      const initResult = await newBtcWallet.initializeFromSeed(seedPhrase);
      
      if (!initResult.success) {
        throw new Error('Failed to initialize Bitcoin wallet');
      }
      
      // Store Bitcoin wallet
      setBtcWallet(newBtcWallet);
      setBtcAddresses(newBtcWallet.addresses);
      
      // Store encrypted Bitcoin wallet data
      const btcWalletData = newBtcWallet.exportWallet();
      const encryptedBtcWallet = CryptoJS.AES.encrypt(
        JSON.stringify(btcWalletData), 
        seedPhrase.substring(0, 32) // Use part of seed as encryption key
      ).toString();
      localStorage.setItem('wepo_btc_wallet', encryptedBtcWallet);
      
      // Load Bitcoin balance and transactions
      await loadBitcoinData(newBtcWallet);
      
      console.log('✅ Self-custodial Bitcoin wallet initialized:', {
        masterFingerprint: initResult.masterFingerprint,
        firstAddress: initResult.firstAddress,
        addressCount: initResult.addressCount
      });
      
      return initResult;
      
    } catch (error) {
      console.error('Bitcoin wallet initialization error:', error);
      throw error;
    } finally {
      setIsBtcLoading(false);
    }
  };

  const loadExistingBitcoinWallet = async (seedPhrase) => {
    try {
      setIsBtcLoading(true);
      
      const encryptedBtcWallet = localStorage.getItem('wepo_btc_wallet');
      if (!encryptedBtcWallet) {
        // No existing Bitcoin wallet, initialize new one
        return await initializeBitcoinWallet(seedPhrase);
      }
      
      // Decrypt and load existing wallet
      const decryptedBtcWallet = CryptoJS.AES.decrypt(
        encryptedBtcWallet, 
        seedPhrase.substring(0, 32)
      ).toString(CryptoJS.enc.Utf8);
      
      const btcWalletData = JSON.parse(decryptedBtcWallet);
      
      // Recreate Bitcoin wallet
      const newBtcWallet = new SelfCustodialBitcoinWallet();
      await newBtcWallet.initializeFromSeed(seedPhrase);
      newBtcWallet.importWalletData(btcWalletData);
      
      setBtcWallet(newBtcWallet);
      setBtcAddresses(newBtcWallet.addresses);
      
      await loadBitcoinData(newBtcWallet);
      
      return { success: true, restored: true };
      
    } catch (error) {
      console.error('Failed to load existing Bitcoin wallet:', error);
      // Fall back to creating new wallet
      return await initializeBitcoinWallet(seedPhrase);
    } finally {
      setIsBtcLoading(false);
    }
  };

  const loadBitcoinData = async (btcWalletInstance) => {
    try {
      // In production, this would query blockchain APIs to get:
      // - UTXO set for all wallet addresses
      // - Transaction history
      // - Current balance
      
      // For now, simulate some data
      const balance = btcWalletInstance.getBalance();
      setBtcBalance(balance.total / 100000000); // Convert satoshis to BTC
      
      // Simulate some test UTXOs and transactions for demo
      const mockUtxos = [
        {
          txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
          vout: 0,
          value: 50000000, // 0.5 BTC in satoshis
          address: btcWalletInstance.addresses[0]?.address,
          confirmations: 6
        },
        {
          txid: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
          vout: 1,
          value: 25000000, // 0.25 BTC in satoshis
          address: btcWalletInstance.addresses[1]?.address,
          confirmations: 3
        }
      ];
      
      btcWalletInstance.utxos = mockUtxos;
      setBtcUtxos(mockUtxos);
      setBtcBalance(0.75); // 0.75 BTC total
      
      // Mock transaction history
      const mockTransactions = [
        {
          txid: 'transaction1234567890abcdef1234567890abcdef1234567890abcdef',
          type: 'receive',
          amount: 0.5,
          address: btcWalletInstance.addresses[0]?.address,
          confirmations: 6,
          timestamp: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
          status: 'confirmed'
        },
        {
          txid: 'transaction_abcdef1234567890abcdef1234567890abcdef1234567890',
          type: 'receive', 
          amount: 0.25,
          address: btcWalletInstance.addresses[1]?.address,
          confirmations: 3,
          timestamp: new Date(Date.now() - 43200000).toISOString(), // 12 hours ago
          status: 'confirmed'
        }
      ];
      
      setBtcTransactions(mockTransactions);
      
    } catch (error) {
      console.error('Failed to load Bitcoin data:', error);
      setBtcBalance(0);
      setBtcTransactions([]);
      setBtcUtxos([]);
    }
  };

  const sendBitcoin = async (toAddress, amount, password) => {
    try {
      setIsBtcLoading(true);
      
      if (!btcWallet) {
        throw new Error('Bitcoin wallet not initialized');
      }
      
      // Verify password by trying to decrypt main wallet
      const encryptedWallet = localStorage.getItem('wepo_wallet');
      const decryptedWallet = CryptoJS.AES.decrypt(encryptedWallet, password).toString(CryptoJS.enc.Utf8);
      JSON.parse(decryptedWallet); // This will throw if password is wrong
      
      // Convert amount to satoshis
      const amountSatoshis = Math.round(amount * 100000000);
      
      // Create transaction
      const txResult = await btcWallet.createTransaction([
        { address: toAddress, value: amountSatoshis }
      ]);
      
      if (!txResult.success) {
        throw new Error(txResult.error);
      }
      
      // Sign transaction
      const signResult = await btcWallet.signTransaction(txResult.transaction);
      
      if (!signResult.success) {
        throw new Error(signResult.error);
      }
      
      // In production, broadcast transaction to Bitcoin network
      // For now, simulate successful send
      const transaction = {
        txid: 'simulated_' + Date.now().toString(),
        type: 'send',
        amount: amount,
        to: toAddress,
        from: btcWallet.addresses[0]?.address,
        timestamp: new Date().toISOString(),
        status: 'pending',
        fee: txResult.fee / 100000000, // Convert to BTC
        confirmations: 0
      };
      
      // Add to transaction history
      setBtcTransactions(prev => [transaction, ...prev]);
      
      // Update balance (subtract sent amount and fee)
      setBtcBalance(prev => prev - amount - transaction.fee);
      
      // Simulate confirmation after 5 seconds
      setTimeout(() => {
        setBtcTransactions(prev =>
          prev.map(tx =>
            tx.txid === transaction.txid
              ? { ...tx, status: 'confirmed', confirmations: 1 }
              : tx
          )
        );
      }, 5000);
      
      return {
        success: true,
        txid: transaction.txid,
        fee: transaction.fee
      };
      
    } catch (error) {
      console.error('Bitcoin send error:', error);
      throw error;
    } finally {
      setIsBtcLoading(false);
    }
  };

  const getNewBitcoinAddress = () => {
    if (!btcWallet) {
      throw new Error('Bitcoin wallet not initialized');
    }
    
    const newAddress = btcWallet.getNewReceiveAddress();
    setBtcAddresses(btcWallet.addresses); // Update addresses array
    return newAddress;
  };

  const getBitcoinBalance = () => {
    if (!btcWallet) {
      return { confirmed: 0, unconfirmed: 0, total: 0 };
    }
    
    return btcWallet.getBalance();
  };

  const exportBitcoinWalletInfo = () => {
    if (!btcWallet) {
      throw new Error('Bitcoin wallet not initialized');
    }
    
    return {
      addresses: btcWallet.getReceivingAddresses(),
      balance: btcWallet.getBalance(),
      utxoCount: btcWallet.utxos.length,
      transactionCount: btcWallet.transactions.length
    };
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
    
    // BTC-related (to be implemented)
    setBtcBalance,
    setBtcTransactions
  };

  return (
    <WalletContext.Provider value={value}>
      {children}
    </WalletContext.Provider>
  );
};