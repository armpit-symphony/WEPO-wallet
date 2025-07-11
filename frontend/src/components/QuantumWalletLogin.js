import React, { useState } from 'react';
import { Shield, Eye, EyeOff, AlertTriangle, ArrowLeft, Zap } from 'lucide-react';
import { useQuantum } from '../contexts/QuantumContext';

const QuantumWalletLogin = ({ onLoginSuccess, onBackToRegular }) => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const { loginQuantumWallet, dilithiumInfo } = useQuantum();

  const validateForm = () => {
    const newErrors = {};

    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;

    setIsLoading(true);
    try {
      await loginQuantumWallet(formData.username, formData.password);
      onLoginSuccess();
    } catch (error) {
      setErrors({ submit: error.message });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 rounded-2xl shadow-2xl border border-purple-500/30 p-8 w-full max-w-md">
        <div className="text-center mb-6">
          <div className="mx-auto mb-4 w-16 h-16 bg-purple-600/20 rounded-full flex items-center justify-center">
            <Shield className="h-8 w-8 text-purple-400" />
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">
            Quantum Wallet Login
          </h2>
          <p className="text-gray-300 text-sm">
            Access your quantum-resistant wallet
          </p>
        </div>

        {/* Back Button */}
        <button
          onClick={onBackToRegular}
          className="flex items-center gap-2 text-gray-400 hover:text-gray-300 mb-4 transition-colors"
        >
          <ArrowLeft size={16} />
          <span className="text-sm">Back to Regular Login</span>
        </button>

        {/* Quantum Status */}
        <div className="mb-6 bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-lg p-4">
          <div className="flex items-center gap-3 mb-2">
            <Zap className="h-5 w-5 text-yellow-400" />
            <h3 className="text-white font-medium text-sm">Quantum Protection Active</h3>
          </div>
          <div className="text-xs text-gray-300 space-y-1">
            <div>• Dilithium2 post-quantum signatures</div>
            <div>• 128-bit quantum security level</div>
            <div>• BLAKE2b quantum-resistant hashing</div>
          </div>
        </div>

        {/* Dilithium Info */}
        {dilithiumInfo && (
          <div className="mb-6 bg-gray-900/50 rounded-lg p-4">
            <h3 className="text-white font-medium mb-2 text-sm">Implementation Status</h3>
            <div className="text-xs text-gray-400">
              <div className="flex justify-between">
                <span>Algorithm:</span>
                <span className="text-purple-300">{dilithiumInfo.algorithm}</span>
              </div>
              <div className="flex justify-between">
                <span>Status:</span>
                <span className={`${dilithiumInfo.ready_for_production ? 'text-green-400' : 'text-yellow-400'}`}>
                  {dilithiumInfo.ready_for_production ? 'Production Ready' : 'Development'}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Quantum Resistant:</span>
                <span className="text-green-400">
                  {dilithiumInfo.quantum_resistant ? '✓ Yes' : '✗ No'}
                </span>
              </div>
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
                Accessing Quantum Wallet...
              </div>
            ) : (
              'Login to Quantum Wallet'
            )}
          </button>
        </form>

        <div className="mt-6 text-center">
          <div className="text-xs text-gray-500">
            🔒 Secured with post-quantum cryptography
          </div>
        </div>
      </div>
    </div>
  );
};

export default QuantumWalletLogin;