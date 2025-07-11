import React, { useState } from 'react';
import { Shield, Zap, Lock, Eye, EyeOff, AlertTriangle, CheckCircle, ArrowLeft } from 'lucide-react';
import { useQuantum } from '../contexts/QuantumContext';

const QuantumWalletSetup = ({ onSetupComplete, onBackToRegular }) => {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: ''
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [walletCreated, setWalletCreated] = useState(false);
  const [walletInfo, setWalletInfo] = useState(null);

  const { createQuantumWallet, dilithiumInfo } = useQuantum();

  const validateForm = () => {
    const newErrors = {};

    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    } else if (formData.username.length < 3) {
      newErrors.username = 'Username must be at least 3 characters';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 8) {
      newErrors.password = 'Password must be at least 8 characters';
    }

    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;

    setIsLoading(true);
    try {
      const result = await createQuantumWallet(
        formData.username, 
        formData.password, 
        formData.confirmPassword
      );
      
      setWalletInfo(result);
      setWalletCreated(true);
    } catch (error) {
      setErrors({ submit: error.message });
    } finally {
      setIsLoading(false);
    }
  };

  const handleComplete = () => {
    onSetupComplete();
  };

  if (walletCreated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl shadow-2xl border border-purple-500/30 p-8 w-full max-w-md">
          <div className="text-center mb-6">
            <div className="mx-auto mb-4 w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center">
              <CheckCircle className="h-8 w-8 text-green-400" />
            </div>
            <h2 className="text-2xl font-bold text-white mb-2">
              Quantum Wallet Created!
            </h2>
            <p className="text-gray-300 text-sm">
              Your quantum-resistant wallet is ready
            </p>
          </div>

          <div className="space-y-4 mb-6">
            <div className="bg-gray-900/50 rounded-lg p-4">
              <h3 className="text-white font-medium mb-2">Wallet Information</h3>
              <div className="space-y-2 text-sm">
                <div>
                  <span className="text-gray-400">Algorithm:</span>
                  <span className="text-purple-300 ml-2">Dilithium2</span>
                </div>
                <div>
                  <span className="text-gray-400">Security Level:</span>
                  <span className="text-green-300 ml-2">128-bit Quantum Resistant</span>
                </div>
                <div>
                  <span className="text-gray-400">Address:</span>
                  <div className="text-purple-300 font-mono text-xs mt-1 break-all">
                    {walletInfo?.address}
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <Shield className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-blue-300 font-medium text-sm">Quantum Protection</h4>
                  <p className="text-blue-200 text-xs mt-1">
                    Your wallet uses Dilithium post-quantum cryptography, protecting against 
                    both classical and quantum computer attacks.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={handleComplete}
            className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 
                     text-white font-medium py-3 px-4 rounded-lg transition-all duration-200 
                     focus:outline-none focus:ring-2 focus:ring-purple-500"
          >
            Continue to Quantum Wallet
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 rounded-2xl shadow-2xl border border-purple-500/30 p-8 w-full max-w-md">
        <div className="text-center mb-6">
          <div className="mx-auto mb-4 w-16 h-16 bg-purple-600/20 rounded-full flex items-center justify-center">
            <Shield className="h-8 w-8 text-purple-400" />
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">
            Create Quantum Wallet
          </h2>
          <p className="text-gray-300 text-sm">
            Post-quantum cryptography for ultimate security
          </p>
        </div>

        {/* Back Button */}
        <button
          onClick={onBackToRegular}
          className="flex items-center gap-2 text-gray-400 hover:text-gray-300 mb-4 transition-colors"
        >
          <ArrowLeft size={16} />
          <span className="text-sm">Back to Regular Wallet</span>
        </button>

        {/* Quantum Features */}
        <div className="mb-6 space-y-3">
          <div className="flex items-center gap-3 text-sm">
            <Zap className="h-4 w-4 text-yellow-400" />
            <span className="text-gray-300">Dilithium2 signatures (2420 bytes)</span>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <Shield className="h-4 w-4 text-green-400" />
            <span className="text-gray-300">128-bit quantum security level</span>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <Lock className="h-4 w-4 text-blue-400" />
            <span className="text-gray-300">BLAKE2b quantum-resistant hashing</span>
          </div>
        </div>

        {/* Dilithium Info */}
        {dilithiumInfo && (
          <div className="mb-6 bg-gray-900/50 rounded-lg p-4">
            <h3 className="text-white font-medium mb-2 text-sm">Implementation Details</h3>
            <div className="space-y-1 text-xs text-gray-400">
              <div>Status: <span className="text-green-400">{dilithiumInfo.status}</span></div>
              <div>Public Key: <span className="text-purple-300">{dilithiumInfo.public_key_size} bytes</span></div>
              <div>Private Key: <span className="text-purple-300">{dilithiumInfo.private_key_size} bytes</span></div>
              <div>Signature: <span className="text-purple-300">{dilithiumInfo.signature_size} bytes</span></div>
            </div>
          </div>
        )}

        {errors.submit && (
          <div className="mb-4 bg-red-900/20 border border-red-500/30 rounded-lg p-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-300 text-sm">{errors.submit}</p>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">
              Username
            </label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
              className={`w-full px-4 py-3 bg-gray-900 border rounded-lg text-white placeholder-gray-500 
                         focus:outline-none focus:ring-2 focus:ring-purple-500 transition-colors
                         ${errors.username ? 'border-red-500' : 'border-gray-600'}`}
              placeholder="Enter your username"
              disabled={isLoading}
            />
            {errors.username && (
              <p className="text-red-400 text-sm mt-1">{errors.username}</p>
            )}
          </div>

          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={formData.password}
                onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
                className={`w-full px-4 py-3 bg-gray-900 border rounded-lg text-white placeholder-gray-500 
                           focus:outline-none focus:ring-2 focus:ring-purple-500 transition-colors pr-12
                           ${errors.password ? 'border-red-500' : 'border-gray-600'}`}
                placeholder="Enter your password"
                disabled={isLoading}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-300"
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>
            {errors.password && (
              <p className="text-red-400 text-sm mt-1">{errors.password}</p>
            )}
          </div>

          <div>
            <label className="block text-gray-300 text-sm font-medium mb-2">
              Confirm Password
            </label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={formData.confirmPassword}
                onChange={(e) => setFormData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                className={`w-full px-4 py-3 bg-gray-900 border rounded-lg text-white placeholder-gray-500 
                           focus:outline-none focus:ring-2 focus:ring-purple-500 transition-colors pr-12
                           ${errors.confirmPassword ? 'border-red-500' : 'border-gray-600'}`}
                placeholder="Confirm your password"
                disabled={isLoading}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-300"
              >
                {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>
            {errors.confirmPassword && (
              <p className="text-red-400 text-sm mt-1">{errors.confirmPassword}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 
                     disabled:from-gray-600 disabled:to-gray-600 text-white font-medium py-3 px-4 rounded-lg 
                     transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-purple-500
                     disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <div className="flex items-center justify-center gap-2">
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                Creating Quantum Wallet...
              </div>
            ) : (
              'Create Quantum Wallet'
            )}
          </button>
        </form>

        <div className="mt-6 text-center">
          <div className="text-xs text-gray-500">
            🔒 Protected by Dilithium post-quantum cryptography
          </div>
        </div>
      </div>
    </div>
  );
};

export default QuantumWalletSetup;