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
    // Show loading state
    if (isLoading) {
      return (
        <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 flex items-center justify-center p-4">
          <div className="text-white text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-400 mx-auto mb-4"></div>
            <p>Loading WEPO Wallet...</p>
          </div>
        </div>
      );
    }

    // Show dashboard if logged in
    if (isLoggedIn) {
      return <Dashboard />;
    }

    // Show wallet setup if no wallets exist
    if (!isWalletSetup && !isQuantumWalletSetup) {
      return <WalletModeSelector onSetupComplete={handleSetupComplete} />;
    }

    // Show appropriate login screen
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
    }

    if (!isQuantumMode && isWalletSetup) {
      return (
        <WalletLogin 
          onLoginSuccess={handleLoginSuccess}
        />
      );
    }

    // Fallback to wallet mode selector
    return <WalletModeSelector onSetupComplete={handleSetupComplete} />;
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