import React, { useState } from 'react';
import { Shield, Zap, Lock, ArrowRight, AlertTriangle, Info } from 'lucide-react';
import WalletSetup from './WalletSetup';
import QuantumWalletSetup from './QuantumWalletSetup';

const WalletModeSelector = ({ onSetupComplete }) => {
  const [selectedMode, setSelectedMode] = useState(null);
  const [showSetup, setShowSetup] = useState(false);

  if (showSetup) {
    if (selectedMode === 'quantum') {
      return (
        <QuantumWalletSetup 
          onSetupComplete={onSetupComplete}
          onBackToRegular={() => {
            setShowSetup(false);
            setSelectedMode(null);
          }}
        />
      );
    } else {
      return (
        <WalletSetup 
          onSetupComplete={onSetupComplete}
        />
      );
    }
  }

  const handleModeSelect = (mode) => {
    setSelectedMode(mode);
    setShowSetup(true);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 rounded-2xl shadow-2xl border border-purple-500/30 p-8 w-full max-w-2xl">
        <div className="text-center mb-8">
          <div className="mx-auto mb-4 w-16 h-16 bg-purple-600/20 rounded-full flex items-center justify-center">
            <Shield className="h-8 w-8 text-purple-400" />
          </div>
          <h2 className="text-3xl font-bold text-white mb-2">
            Choose Your Wallet Type
          </h2>
          <p className="text-gray-300">
            Select the security level that's right for you
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Regular Wallet */}
          <div className="bg-gray-900/50 border border-gray-600 rounded-xl p-6 hover:border-gray-500 transition-colors cursor-pointer group"
               onClick={() => handleModeSelect('regular')}>
            <div className="text-center mb-4">
              <div className="mx-auto mb-3 w-12 h-12 bg-blue-600/20 rounded-full flex items-center justify-center">
                <Shield className="h-6 w-6 text-blue-400" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Regular Wallet</h3>
              <p className="text-gray-400 text-sm">Standard cryptographic security</p>
            </div>

            <div className="space-y-3 mb-6">
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                <span className="text-gray-300">256-bit ECDSA signatures</span>
              </div>
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                <span className="text-gray-300">SHA-256 cryptographic hashing</span>
              </div>
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                <span className="text-gray-300">BIP39 seed phrase recovery</span>
              </div>
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                <span className="text-gray-300">Compatible with all features</span>
              </div>
            </div>

            <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-3 mb-4">
              <div className="flex items-start gap-2">
                <Info className="h-4 w-4 text-blue-400 flex-shrink-0 mt-0.5" />
                <p className="text-blue-200 text-xs">
                  Recommended for most users. Provides excellent security using proven cryptographic standards.
                </p>
              </div>
            </div>

            <button className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors group-hover:bg-blue-700 flex items-center justify-center gap-2">
              Create Regular Wallet
              <ArrowRight size={16} />
            </button>
          </div>

          {/* Quantum Wallet */}
          <div className="bg-gray-900/50 border border-purple-600 rounded-xl p-6 hover:border-purple-500 transition-colors cursor-pointer group relative overflow-hidden"
               onClick={() => handleModeSelect('quantum')}>
            {/* Quantum glow effect */}
            <div className="absolute inset-0 bg-gradient-to-r from-purple-600/10 to-blue-600/10 opacity-50"></div>
            
            <div className="relative text-center mb-4">
              <div className="mx-auto mb-3 w-12 h-12 bg-purple-600/20 rounded-full flex items-center justify-center">
                <Zap className="h-6 w-6 text-purple-400" />
              </div>
              <div className="flex items-center justify-center gap-2 mb-2">
                <h3 className="text-xl font-bold text-white">Quantum Wallet</h3>
                <span className="bg-gradient-to-r from-purple-500 to-pink-500 text-white text-xs px-2 py-1 rounded-full font-medium">
                  NEW
                </span>
              </div>
              <p className="text-gray-400 text-sm">Post-quantum cryptographic security</p>
            </div>

            <div className="relative space-y-3 mb-6">
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                <span className="text-gray-300">Dilithium2 quantum-resistant signatures</span>
              </div>
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                <span className="text-gray-300">BLAKE2b quantum-resistant hashing</span>
              </div>
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                <span className="text-gray-300">128-bit quantum security level</span>
              </div>
              <div className="flex items-center gap-3 text-sm">
                <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                <span className="text-gray-300">Future-proof against quantum attacks</span>
              </div>
            </div>

            <div className="relative bg-purple-900/20 border border-purple-500/30 rounded-lg p-3 mb-4">
              <div className="flex items-start gap-2">
                <Lock className="h-4 w-4 text-purple-400 flex-shrink-0 mt-0.5" />
                <p className="text-purple-200 text-xs">
                  Revolutionary security designed to protect against future quantum computer attacks. 
                  Uses NIST-approved post-quantum cryptography.
                </p>
              </div>
            </div>

            <button className="relative w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-all duration-200 group-hover:from-purple-700 group-hover:to-blue-700 flex items-center justify-center gap-2">
              Create Quantum Wallet
              <ArrowRight size={16} />
            </button>
          </div>
        </div>

        {/* Comparison Note */}
        <div className="mt-8 bg-gray-900/50 border border-gray-600 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="text-white font-medium text-sm mb-1">Important Note</h4>
              <p className="text-gray-300 text-sm">
                Both wallet types are fully functional and secure. Quantum wallets provide additional protection 
                against future quantum computing threats, while regular wallets use current industry standards.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-6 text-center">
          <p className="text-xs text-gray-500">
            You can always create additional wallets later
          </p>
        </div>
      </div>
    </div>
  );
};

export default WalletModeSelector;