import React, { useState, useEffect } from 'react';
import './App.css';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import WalletModeSelector from './components/WalletModeSelector';
import WalletLogin from './components/WalletLogin';
import QuantumWalletLogin from './components/QuantumWalletLogin';
import Dashboard from './components/Dashboard';
import { WalletProvider } from './contexts/WalletContext';
import { QuantumProvider } from './contexts/QuantumContext';

function App() {
  const [isWalletSetup, setIsWalletSetup] = useState(false);
  const [isQuantumWalletSetup, setIsQuantumWalletSetup] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isQuantumMode, setIsQuantumMode] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Initialize authentication state
    const initAuth = async () => {
      try {
        // Check if regular wallet exists
        const walletExists = localStorage.getItem('wepo_wallet_exists');
        const sessionActive = sessionStorage.getItem('wepo_session_active');
        
        // Check if quantum wallet exists
        const quantumWalletExists = localStorage.getItem('wepo_quantum_wallet_exists');
        const quantumSessionActive = sessionStorage.getItem('wepo_quantum_session_active');
        const quantumMode = localStorage.getItem('wepo_quantum_mode') === 'true';
        
        setIsWalletSetup(!!walletExists);
        setIsQuantumWalletSetup(!!quantumWalletExists);
        setIsQuantumMode(quantumMode);
        
        // Simplified login check
        const shouldBeLoggedIn = (quantumMode && quantumSessionActive) || (!quantumMode && sessionActive);
        setIsLoggedIn(shouldBeLoggedIn);
        
        console.log('Auth initialized:', {
          walletExists: !!walletExists,
          quantumWalletExists: !!quantumWalletExists,
          quantumMode,
          sessionActive: !!sessionActive,
          quantumSessionActive: !!quantumSessionActive,
          isLoggedIn: shouldBeLoggedIn
        });
      } catch (error) {
        console.error('Auth initialization error:', error);
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const handleSetupComplete = () => {
    // Simplified setup completion
    const quantumMode = localStorage.getItem('wepo_quantum_mode') === 'true';
    const walletExists = localStorage.getItem('wepo_wallet_exists');
    const quantumWalletExists = localStorage.getItem('wepo_quantum_wallet_exists');
    
    // Update wallet setup states
    setIsWalletSetup(!!walletExists);
    setIsQuantumWalletSetup(!!quantumWalletExists);
    setIsQuantumMode(quantumMode);
    
    // Auto-login after setup - simplified logic
    if (quantumMode) {
      sessionStorage.setItem('wepo_quantum_session_active', 'true');
    } else {
      sessionStorage.setItem('wepo_session_active', 'true');
    }
    
    setIsLoggedIn(true);
    
    console.log('Setup complete - auto-login successful:', {
      quantumMode,
      walletExists: !!walletExists,
      quantumWalletExists: !!quantumWalletExists
    });
  };

  const handleLoginSuccess = () => {
    setIsLoggedIn(true);
  };

  const renderAuthFlow = () => {
    try {
      // If no wallets exist, show mode selector
      if (!isWalletSetup && !isQuantumWalletSetup) {
        return <WalletModeSelector onSetupComplete={handleSetupComplete} />;
      }
      
      // If logged in, show dashboard
      if (isLoggedIn) {
        return <Dashboard />;
      }
      
      // Show appropriate login based on mode and available wallets
      if (isQuantumMode && isQuantumWalletSetup) {
        return (
          <QuantumWalletLogin 
            onLoginSuccess={handleLoginSuccess}
            onBackToRegular={() => {
              setIsQuantumMode(false);
              localStorage.setItem('wepo_quantum_mode', 'false');
            }}
          />
        );
      } else if (!isQuantumMode && isWalletSetup) {
        return (
          <WalletLogin 
            onLoginSuccess={handleLoginSuccess}
          />
        );
      } else {
        // Handle edge cases - show mode selector
        console.warn('Edge case in auth flow:', {
          isQuantumMode,
          isWalletSetup,
          isQuantumWalletSetup,
          isLoggedIn
        });
        return <WalletModeSelector onSetupComplete={handleSetupComplete} />;
      }
    } catch (error) {
      console.error('Auth flow error:', error);
      return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
          <div className="bg-red-900/50 border border-red-500 rounded-lg p-6 text-red-200 max-w-md">
            <h2 className="text-xl font-bold mb-2">Authentication Error</h2>
            <p className="mb-4">There was an error loading the wallet interface.</p>
            <button 
              onClick={() => window.location.reload()}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }
  };

  return (
    <WalletProvider>
      <QuantumProvider>
        <div className="App">
          <Router>
            <Routes>
              <Route 
                path="/" 
                element={renderAuthFlow()}
              />
              <Route 
                path="/setup" 
                element={
                  (isWalletSetup || isQuantumWalletSetup) ? (
                    <Navigate to="/" replace />
                  ) : (
                    <WalletModeSelector onSetupComplete={handleSetupComplete} />
                  )
                } 
              />
              <Route 
                path="/login" 
                element={
                  (!isWalletSetup && !isQuantumWalletSetup) ? (
                    <Navigate to="/setup" replace />
                  ) : isLoggedIn ? (
                    <Navigate to="/" replace />
                  ) : (
                    renderAuthFlow()
                  )
                } 
              />
            </Routes>
          </Router>
        </div>
      </QuantumProvider>
    </WalletProvider>
  );
}

export default App;