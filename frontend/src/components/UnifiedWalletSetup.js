import React, { useState } from 'react';
import { 
  Eye, 
  EyeOff, 
  Copy, 
  ArrowLeft, 
  Check, 
  Bitcoin, 
  Coins,
  Shield,
  AlertTriangle
} from 'lucide-react';
import { useUnifiedWallet } from '../contexts/UnifiedWalletContext';

const UnifiedWalletSetup = ({ onWalletCreated, onBack }) => {
  const { createWallet, isLoading, showSeedPhrase, setShowSeedPhrase, setSeedConfirmed } = useUnifiedWallet();
  
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: ''
  });
  const [formErrors, setFormErrors] = useState({});
  const [step, setStep] = useState('form'); // 'form', 'seed', 'confirm'
  const [generatedWallet, setGeneratedWallet] = useState(null);
  const [seedCopied, setSeedCopied] = useState(false);
  const [seedConfirmChecked, setSeedConfirmChecked] = useState(false);

  const validateForm = () => {
    const errors = {};
    
    if (!formData.username || formData.username.length < 3) {
      errors.username = 'Username must be at least 3 characters';
    }
    
    if (!formData.password || formData.password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
    }
    
    if (formData.password !== formData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }
    
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    try {
      const wallet = await createWallet(formData.username, formData.password);
      setGeneratedWallet(wallet);
      setStep('seed');
    } catch (error) {
      setFormErrors({ submit: error.message });
    }
  };

  const handleSeedConfirm = () => {
    if (seedConfirmChecked) {
      setSeedConfirmed(true);
      setShowSeedPhrase(false);
      setStep('complete');
      setTimeout(() => {
        onWalletCreated();
      }, 1500);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setSeedCopied(true);
    setTimeout(() => setSeedCopied(false), 2000);
  };

  if (step === 'complete') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl shadow-2xl border border-green-500/30 p-8 w-full max-w-md text-center">
          <div className="mx-auto mb-6 w-16 h-16 bg-green-600/20 rounded-full flex items-center justify-center">
            <Check className="h-8 w-8 text-green-400" />
          </div>
          <h2 className="text-2xl font-bold text-white mb-4">
            Unified Wallet Created!
          </h2>
          <p className="text-gray-300 mb-6">
            Your Bitcoin + WEPO wallet is ready to use
          </p>
          <div className="flex items-center justify-center gap-2 text-sm text-gray-400">
            <Bitcoin className="h-4 w-4 text-orange-400" />
            <span>+</span>
            <Coins className="h-4 w-4 text-purple-400" />
            <span>= One Wallet</span>
          </div>
        </div>
      </div>
    );
  }

  if (step === 'seed' && generatedWallet) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl shadow-2xl border border-purple-500/30 p-8 w-full max-w-2xl">
          <div className="text-center mb-8">
            <div className="mx-auto mb-4 w-16 h-16 bg-red-600/20 rounded-full flex items-center justify-center">
              <Shield className="h-8 w-8 text-red-400" />
            </div>
            <h2 className="text-3xl font-bold text-white mb-2">
              Backup Your Seed Phrase
            </h2>
            <p className="text-gray-300">
              This controls both your Bitcoin and WEPO addresses
            </p>
          </div>

          {/* Seed Phrase Display */}
          <div className="bg-gray-900/50 border border-gray-600 rounded-xl p-6 mb-6">
            <div className="grid grid-cols-3 md:grid-cols-4 gap-3 mb-4">
              {generatedWallet.mnemonic.split(' ').map((word, index) => (
                <div key={index} className="bg-gray-700 rounded-lg p-3 text-center">
                  <div className="text-xs text-gray-400 mb-1">{index + 1}</div>
                  <div className="text-white font-medium">{word}</div>
                </div>
              ))}
            </div>
            
            <button
              onClick={() => copyToClipboard(generatedWallet.mnemonic)}
              className="w-full bg-purple-600 hover:bg-purple-700 text-white py-2 rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
            >
              <Copy className="h-4 w-4" />
              {seedCopied ? 'Copied!' : 'Copy Seed Phrase'}
            </button>
          </div>

          {/* Wallet Addresses */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="bg-orange-900/20 border border-orange-500/30 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Bitcoin className="h-5 w-5 text-orange-400" />
                <span className="text-white font-medium">Bitcoin Address</span>
              </div>
              <div className="text-xs text-gray-300 break-all font-mono">
                {generatedWallet.btc.address}
              </div>
            </div>
            
            <div className="bg-purple-900/20 border border-purple-500/30 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Coins className="h-5 w-5 text-purple-400" />
                <span className="text-white font-medium">WEPO Address</span>
              </div>
              <div className="text-xs text-gray-300 break-all font-mono">
                {generatedWallet.wepo.address}
              </div>
            </div>
          </div>

          {/* Warning */}
          <div className="bg-red-900/20 border border-red-500/30 rounded-xl p-4 mb-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5 shrink-0" />
              <div>
                <h4 className="text-red-400 font-medium mb-2">Critical Security Warning</h4>
                <ul className="text-red-200 text-sm space-y-1">
                  <li>• Write down your seed phrase on paper</li>
                  <li>• Store it in a secure location</li>
                  <li>• Never share it with anyone</li>
                  <li>• Without it, you'll lose access to both BTC and WEPO</li>
                  <li>• This seed controls both currencies in your unified wallet</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Confirmation */}
          <div className="space-y-4">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={seedConfirmChecked}
                onChange={(e) => setSeedConfirmChecked(e.target.checked)}
                className="mt-1 h-4 w-4 text-purple-600 focus:ring-purple-500 border-gray-600 rounded bg-gray-700"
              />
              <span className="text-white text-sm">
                I have securely written down my seed phrase and understand that losing it means 
                losing access to both my Bitcoin and WEPO funds permanently.
              </span>
            </label>

            <div className="flex gap-4">
              <button
                onClick={onBack}
                className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
              >
                <ArrowLeft className="h-4 w-4" />
                Back
              </button>
              
              <button
                onClick={handleSeedConfirm}
                disabled={!seedConfirmChecked}
                className="flex-1 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white py-3 rounded-lg font-medium transition-colors"
              >
                I Have Secured My Recovery Phrase
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 rounded-2xl shadow-2xl border border-purple-500/30 p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="mx-auto mb-4 w-16 h-16 bg-orange-600/20 rounded-full flex items-center justify-center">
            <div className="flex -space-x-1">
              <Bitcoin className="h-6 w-6 text-orange-400 z-10" />
              <Coins className="h-6 w-6 text-purple-400" />
            </div>
          </div>
          <h2 className="text-3xl font-bold text-white mb-2">
            Create Unified Wallet
          </h2>
          <p className="text-gray-300">
            One wallet for Bitcoin and WEPO
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Username
            </label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
              className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-purple-500 focus:outline-none"
              placeholder="Enter your username"
              required
            />
            {formErrors.username && (
              <p className="text-red-400 text-sm mt-1">{formErrors.username}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Password
            </label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
              className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-purple-500 focus:outline-none"
              placeholder="Enter your password"
              required
            />
            {formErrors.password && (
              <p className="text-red-400 text-sm mt-1">{formErrors.password}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Confirm Password
            </label>
            <input
              type="password"
              value={formData.confirmPassword}
              onChange={(e) => setFormData(prev => ({ ...prev, confirmPassword: e.target.value }))}
              className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-purple-500 focus:outline-none"
              placeholder="Confirm your password"
              required
            />
            {formErrors.confirmPassword && (
              <p className="text-red-400 text-sm mt-1">{formErrors.confirmPassword}</p>
            )}
          </div>

          {formErrors.submit && (
            <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
              <p className="text-red-400 text-sm">{formErrors.submit}</p>
            </div>
          )}

          <div className="flex gap-4">
            <button
              type="button"
              onClick={onBack}
              className="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
            >
              <ArrowLeft className="h-4 w-4" />
              Back
            </button>
            
            <button
              type="submit"
              disabled={isLoading}
              className="flex-1 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white py-3 rounded-lg font-medium transition-colors"
            >
              {isLoading ? 'Creating...' : 'Create Wallet'}
            </button>
          </div>
        </form>

        {/* Feature Info */}
        <div className="mt-6 p-4 bg-blue-900/20 border border-blue-500/30 rounded-lg">
          <h4 className="text-blue-400 font-medium mb-2">Unified Wallet Features</h4>
          <ul className="text-blue-200 text-sm space-y-1">
            <li>• Bitcoin and WEPO in one wallet</li>
            <li>• Single seed phrase for both currencies</li>
            <li>• Instant internal BTC ↔ WEPO swaps</li>
            <li>• Ready for Christmas genesis mining</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default UnifiedWalletSetup;