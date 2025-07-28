import React, { useState } from 'react';
import { Shield, Copy, Eye, EyeOff, AlertTriangle } from 'lucide-react';
import { generateMnemonic, validateMnemonic } from 'bip39';

const WalletSetup = ({ onWalletCreated, onLoginRedirect }) => {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: ''
  });
  const [mnemonic, setMnemonic] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [mnemonicCopied, setMnemonicCopied] = useState(false);
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    setError('');
  };

  const validateForm = () => {
    if (!formData.username || formData.username.length < 3) {
      setError('Username must be at least 3 characters long');
      return false;
    }
    if (!formData.password || formData.password.length < 8) {
      setError('Password must be at least 8 characters long');
      return false;
    }
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return false;
    }
    return true;
  };

  const handleCreateWallet = async () => {
    if (!validateForm()) return;

    setIsLoading(true);
    try {
      // PROPER BIP-39 IMPLEMENTATION - CRYPTOGRAPHICALLY SECURE
      // Use the wallet context's secure mnemonic generation
      const secureMnemonic = generateMnemonic();
      
      if (!secureMnemonic) {
        throw new Error('Failed to generate secure seed phrase');
      }
      
      // Validate the generated mnemonic
      if (!validateMnemonic || !validateMnemonic(secureMnemonic)) {
        throw new Error('Generated invalid mnemonic, please try again');
      }
      
      setMnemonic(secureMnemonic);
      
      console.log('✅ Secure BIP-39 seed phrase generated successfully');
      console.log(`📊 Entropy: ${secureMnemonic.split(' ').length} words (${secureMnemonic.split(' ').length * 11} bits)`);
      setStep(2);
    } catch (error) {
      console.error('❌ Seed phrase generation failed:', error);
      setError('Failed to generate secure seed phrase: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const copyMnemonic = () => {
    navigator.clipboard.writeText(mnemonic);
    setMnemonicCopied(true);
    setTimeout(() => setMnemonicCopied(false), 2000);
  };

  const handleFinalizeWallet = async () => {
    if (!agreedToTerms) {
      setError('You must agree to the terms and conditions');
      return;
    }

    setIsLoading(true);
    try {
      // Generate WEPO address from mnemonic using proper crypto
      const crypto = window.crypto || window.msCrypto;
      const encoder = new TextEncoder();
      const data = encoder.encode(mnemonic + formData.username);
      
      // Create cryptographic hash for address
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      const address = `wepo1${hashHex.substring(0, 32)}`;
      
      // Create wallet data with proper structure
      const walletData = {
        username: formData.username,
        address: address,
        mnemonic: mnemonic, // Store mnemonic for wallet context
        encryptedMnemonic: mnemonic, // TODO: Implement proper encryption
        createdAt: new Date().toISOString(),
        balance: 0.0,
        version: '2.0',
        // Add WEPO-specific fields
        wepo: {
          address: address,
          privateKey: hashHex.substring(0, 64) // Simplified for demo
        }
      };
      
      // Store wallet data in localStorage
      localStorage.setItem('wepo_wallet', JSON.stringify(walletData));
      localStorage.setItem('wepo_wallet_exists', 'true');
      localStorage.setItem('wepo_wallet_username', formData.username);
      
      // Set session storage items (like WalletLogin does)
      sessionStorage.setItem('wepo_session_active', 'true');
      sessionStorage.setItem('wepo_current_wallet', JSON.stringify(walletData));
      
      // Set launch date for demo
      if (!localStorage.getItem('wepo_launch_date')) {
        localStorage.setItem('wepo_launch_date', new Date().toISOString());
      }
      
      console.log('✅ Wallet created successfully:', {
        address: address,
        username: formData.username,
        sessionActive: sessionStorage.getItem('wepo_session_active'),
        walletStored: localStorage.getItem('wepo_wallet_exists')
      });
      
      // Small delay to ensure storage is complete
      setTimeout(() => {
        onWalletCreated();
      }, 100);
      
    } catch (error) {
      console.error('Wallet finalization error:', error);
      setError('Failed to create wallet: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-gray-800 rounded-2xl shadow-2xl border border-purple-500/20">
        <div className="p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="flex items-center justify-center mb-4">
              <Shield className="h-12 w-12 text-purple-400" />
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">WEPO Wallet</h1>
            <p className="text-purple-200">We The People - Your Financial Freedom</p>
          </div>

          {/* Step 1: Wallet Creation */}
          {step === 1 && (
            <div className="space-y-6">
              <h2 className="text-xl font-semibold text-white text-center">Create Your Wallet</h2>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-purple-200 mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    name="username"
                    value={formData.username}
                    onChange={handleInputChange}
                    className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
                    placeholder="Enter your username"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-purple-200 mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      name="password"
                      value={formData.password}
                      onChange={handleInputChange}
                      className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-12"
                      placeholder="Enter your password"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-3 text-gray-400 hover:text-purple-400"
                    >
                      {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-purple-200 mb-2">
                    Confirm Password
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-12"
                      placeholder="Confirm your password"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-3 top-3 text-gray-400 hover:text-purple-400"
                    >
                      {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                    </button>
                  </div>
                </div>
              </div>

              {error && (
                <div className="bg-red-900/50 border border-red-500 rounded-lg p-3 text-red-200 text-sm">
                  {error}
                </div>
              )}

              <button
                onClick={handleCreateWallet}
                disabled={isLoading}
                className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Creating Wallet...' : 'Create Wallet'}
              </button>
            </div>
          )}

          {/* Step 2: Seed Phrase Backup */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="text-center">
                <AlertTriangle className="h-12 w-12 text-yellow-400 mx-auto mb-4" />
                <h2 className="text-xl font-semibold text-white mb-2">Backup Your Recovery Phrase</h2>
                <p className="text-purple-200 text-sm">
                  Write down these 12 words in the exact order shown. This is the ONLY way to recover your wallet.
                </p>
              </div>

              <div className="bg-gray-700 rounded-lg p-4 border border-purple-500/30">
                <div className="grid grid-cols-3 gap-2 mb-4">
                  {mnemonic.split(' ').map((word, index) => (
                    <div key={index} className="bg-gray-800 rounded p-2 text-center">
                      <span className="text-xs text-purple-300">{index + 1}</span>
                      <div className="text-white font-mono text-sm">{word}</div>
                    </div>
                  ))}
                </div>
                
                <button
                  onClick={copyMnemonic}
                  className="w-full flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg transition-colors"
                >
                  <Copy size={16} />
                  {mnemonicCopied ? 'Copied!' : 'Copy to Clipboard'}
                </button>
              </div>

              <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5 flex-shrink-0" />
                  <div className="text-red-200 text-sm">
                    <p className="font-semibold mb-1">CRITICAL SECURITY WARNING:</p>
                    <ul className="space-y-1 text-xs">
                      <li>• Save these words in a secure, offline location</li>
                      <li>• Never share your recovery phrase with anyone</li>
                      <li>• WEPO cannot recover your wallet if you lose these words</li>
                      <li>• Anyone with these words can access your funds</li>
                    </ul>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={agreedToTerms}
                    onChange={(e) => setAgreedToTerms(e.target.checked)}
                    className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                  />
                  <span className="text-sm text-purple-200">
                    I understand that I am responsible for keeping my recovery phrase secure and that WEPO cannot recover my wallet if I lose it.
                  </span>
                </label>
              </div>

              <button
                onClick={handleFinalizeWallet}
                disabled={!agreedToTerms || isLoading}
                className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? 'Finalizing...' : 'I Have Secured My Recovery Phrase'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default WalletSetup;