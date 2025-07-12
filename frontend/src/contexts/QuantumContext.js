import React, { createContext, useContext, useState, useEffect } from 'react';
import * as bip39 from 'bip39';
import CryptoJS from 'crypto-js';
import { generateWepoAddress, validateWepoAddress, isQuantumAddress } from '../utils/addressUtils';

const QuantumContext = createContext();

export const useQuantum = () => {
  const context = useContext(QuantumContext);
  if (!context) {
    throw new Error('useQuantum must be used within a QuantumProvider');
  }
  return context;
};

export const QuantumProvider = ({ children }) => {
  const [quantumWallet, setQuantumWallet] = useState(null);
  const [quantumBalance, setQuantumBalance] = useState(0);
  const [isQuantumMode, setIsQuantumMode] = useState(false);
  const [quantumTransactions, setQuantumTransactions] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [quantumStatus, setQuantumStatus] = useState(null);
  const [dilithiumInfo, setDilithiumInfo] = useState(null);

  const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  // Load quantum status on initialization
  useEffect(() => {
    loadQuantumStatus();
    loadDilithiumInfo();
  }, []);

  // Load quantum wallet if exists
  useEffect(() => {
    const storedQuantumMode = localStorage.getItem('wepo_quantum_mode');
    if (storedQuantumMode === 'true') {
      setIsQuantumMode(true);
      loadQuantumWallet();
    }
  }, []);

  const loadQuantumStatus = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/quantum/status`);
      if (response.ok) {
        const status = await response.json();
        setQuantumStatus(status);
      }
    } catch (error) {
      console.error('Failed to load quantum status:', error);
    }
  };

  const loadDilithiumInfo = async () => {
    try {
      const response = await fetch(`${backendUrl}/api/quantum/dilithium`);
      if (response.ok) {
        const info = await response.json();
        setDilithiumInfo(info);
      }
    } catch (error) {
      console.error('Failed to load Dilithium info:', error);
    }
  };

  const loadQuantumWallet = async () => {
    const walletData = localStorage.getItem('wepo_quantum_wallet');
    if (walletData) {
      try {
        const parsedWallet = JSON.parse(walletData);
        setQuantumWallet(parsedWallet);
        await loadQuantumWalletData(parsedWallet.address);
      } catch (error) {
        console.error('Failed to load quantum wallet:', error);
      }
    }
  };

  const loadQuantumWalletData = async (address) => {
    setIsLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/quantum/wallet/${address}`);
      if (response.ok) {
        const data = await response.json();
        setQuantumBalance(data.balance || 0);
        
        // Load quantum transactions (simplified - would need proper endpoint)
        setQuantumTransactions([]);
      } else {
        setQuantumBalance(0);
        setQuantumTransactions([]);
      }
    } catch (error) {
      console.error('Failed to load quantum wallet data:', error);
      setQuantumBalance(0);
      setQuantumTransactions([]);
    } finally {
      setIsLoading(false);
    }
  };

  const createQuantumWallet = async (username, password, confirmPassword) => {
    if (password !== confirmPassword) {
      throw new Error('Passwords do not match');
    }

    setIsLoading(true);
    try {
      // Create quantum wallet via API
      const response = await fetch(`${backendUrl}/api/quantum/wallet/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({})
      });

      if (!response.ok) {
        throw new Error('Failed to create quantum wallet');
      }

      const data = await response.json();
      const quantumWalletData = {
        username,
        address: data.wallet.address,
        publicKey: data.wallet.public_key,
        encryptedPrivateKey: CryptoJS.AES.encrypt(data.wallet.private_key, password).toString(),
        createdAt: new Date().toISOString(),
        algorithm: 'Dilithium2',
        quantumResistant: true
      };

      // Store quantum wallet
      localStorage.setItem('wepo_quantum_wallet', JSON.stringify(quantumWalletData));
      localStorage.setItem('wepo_quantum_wallet_exists', 'true');
      localStorage.setItem('wepo_quantum_mode', 'true');
      
      setQuantumWallet(quantumWalletData);
      setIsQuantumMode(true);
      
      return {
        address: quantumWalletData.address,
        publicKey: quantumWalletData.publicKey,
        algorithm: 'Dilithium2'
      };
    } catch (error) {
      console.error('Quantum wallet creation error:', error);
      throw new Error('Failed to create quantum wallet: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const loginQuantumWallet = async (username, password) => {
    const walletData = localStorage.getItem('wepo_quantum_wallet');
    if (!walletData) {
      throw new Error('Quantum wallet not found');
    }

    try {
      const parsedWallet = JSON.parse(walletData);
      if (parsedWallet.username !== username) {
        throw new Error('Invalid username');
      }

      // Verify password by attempting to decrypt private key
      CryptoJS.AES.decrypt(parsedWallet.encryptedPrivateKey, password).toString(CryptoJS.enc.Utf8);
      
      setQuantumWallet(parsedWallet);
      setIsQuantumMode(true);
      localStorage.setItem('wepo_quantum_mode', 'true');
      sessionStorage.setItem('wepo_quantum_session_active', 'true');
      
      await loadQuantumWalletData(parsedWallet.address);
      
      return parsedWallet;
    } catch (error) {
      throw new Error('Invalid credentials or corrupted wallet data');
    }
  };

  const sendQuantumWepo = async (toAddress, amount, password) => {
    if (!quantumWallet) {
      throw new Error('No quantum wallet available');
    }

    setIsLoading(true);
    try {
      // Decrypt private key
      const decryptedPrivateKey = CryptoJS.AES.decrypt(
        quantumWallet.encryptedPrivateKey, 
        password
      ).toString(CryptoJS.enc.Utf8);
      
      if (!decryptedPrivateKey) {
        throw new Error('Invalid password');
      }

      // Create quantum transaction via API
      const response = await fetch(`${backendUrl}/api/quantum/transaction/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from_address: quantumWallet.address,
          to_address: toAddress,
          amount: parseFloat(amount),
          fee: 0.0001,
          private_key: decryptedPrivateKey
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Transaction failed');
      }

      const data = await response.json();
      
      // Create transaction record
      const transaction = {
        id: data.transaction_id,
        type: 'send',
        amount: parseFloat(amount),
        from: quantumWallet.address,
        to: toAddress,
        timestamp: new Date().toISOString(),
        status: 'pending',
        quantumResistant: true,
        signature: data.signature,
        algorithm: 'Dilithium2'
      };
      
      // Add to quantum transactions
      setQuantumTransactions(prev => [transaction, ...prev]);
      
      // Update balance (optimistic update)
      setQuantumBalance(prev => prev - parseFloat(amount) - 0.0001);
      
      // Simulate confirmation
      setTimeout(() => {
        setQuantumTransactions(prev => 
          prev.map(tx => 
            tx.id === transaction.id 
              ? { ...tx, status: 'confirmed' }
              : tx
          )
        );
      }, 3000);
      
      return transaction;
    } catch (error) {
      throw new Error('Quantum transaction failed: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const toggleQuantumMode = () => {
    const newMode = !isQuantumMode;
    setIsQuantumMode(newMode);
    localStorage.setItem('wepo_quantum_mode', newMode.toString());
    
    if (newMode && quantumWallet) {
      loadQuantumWalletData(quantumWallet.address);
    }
  };

  const validateQuantumAddress = (address) => {
    // Validate quantum WEPO address format
    if (!address || typeof address !== 'string') {
      return false;
    }
    
    // Must start with wepo1 and be 45 characters
    return address.startsWith('wepo1') && address.length === 45;
  };

  const logoutQuantum = () => {
    setQuantumWallet(null);
    setQuantumBalance(0);
    setQuantumTransactions([]);
    setIsQuantumMode(false);
    localStorage.setItem('wepo_quantum_mode', 'false');
    sessionStorage.removeItem('wepo_quantum_session_active');
  };

  const generateQuantumAddress = (seed) => {
    // Use standardized quantum address generation
    return generateWepoAddress(seed, 'quantum');
  };

  const value = {
    // State
    quantumWallet,
    quantumBalance,
    isQuantumMode,
    quantumTransactions,
    isLoading,
    quantumStatus,
    dilithiumInfo,
    
    // Actions
    createQuantumWallet,
    loginQuantumWallet,
    sendQuantumWepo,
    toggleQuantumMode,
    validateQuantumAddress,
    logoutQuantum,
    loadQuantumWalletData,
    loadQuantumStatus,
    loadDilithiumInfo,
    
    // Setters
    setQuantumWallet,
    setQuantumBalance,
    setQuantumTransactions
  };

  return (
    <QuantumContext.Provider value={value}>
      {children}
    </QuantumContext.Provider>
  );
};