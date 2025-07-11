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

  useEffect(() => {
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
    
    // Determine login status based on mode
    if (quantumMode && quantumSessionActive) {
      setIsLoggedIn(true);
    } else if (!quantumMode && sessionActive) {
      setIsLoggedIn(true);
    } else {
      setIsLoggedIn(false);
    }
    
    // Debug logging
    console.log('Auth state check:', {
      walletExists: !!walletExists,
      quantumWalletExists: !!quantumWalletExists,
      quantumMode,
      sessionActive: !!sessionActive,
      quantumSessionActive: !!quantumSessionActive,
      isLoggedIn: (quantumMode && quantumSessionActive) || (!quantumMode && sessionActive)
    });
  }, []);

  const handleSetupComplete = () => {
    // Check which type of wallet was created
    const quantumMode = localStorage.getItem('wepo_quantum_mode') === 'true';
    const walletExists = localStorage.getItem('wepo_wallet_exists');
    const quantumWalletExists = localStorage.getItem('wepo_quantum_wallet_exists');
    
    setIsWalletSetup(!!walletExists);
    setIsQuantumWalletSetup(!!quantumWalletExists);
    setIsQuantumMode(quantumMode);
    
    // Auto-login after setup for better UX
    if (quantumMode && quantumWalletExists) {
      sessionStorage.setItem('wepo_quantum_session_active', 'true');
      setIsLoggedIn(true);
    } else if (!quantumMode && walletExists) {
      sessionStorage.setItem('wepo_session_active', 'true');
      setIsLoggedIn(true);
    }
    
    console.log('Setup complete:', {
      quantumMode,
      walletExists: !!walletExists,
      quantumWalletExists: !!quantumWalletExists,
      autoLogin: true
    });
  };

  const handleLoginSuccess = () => {
    setIsLoggedIn(true);
  };

  const renderAuthFlow = () => {
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
      return <WalletModeSelector onSetupComplete={handleSetupComplete} />;
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