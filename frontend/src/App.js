import React, { useState, useEffect } from 'react';
import './App.css';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import WalletSetup from './components/WalletSetup';
import WalletLogin from './components/WalletLogin';
import Dashboard from './components/Dashboard';
import { WalletProvider } from './contexts/WalletContext';

function App() {
  const [isWalletSetup, setIsWalletSetup] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    // Check if wallet exists in localStorage
    const walletExists = localStorage.getItem('wepo_wallet_exists');
    const sessionActive = sessionStorage.getItem('wepo_session_active');
    
    setIsWalletSetup(!!walletExists);
    setIsLoggedIn(!!sessionActive);
  }, []);

  return (
    <WalletProvider>
      <div className="App">
        <Router>
          <Routes>
            <Route 
              path="/" 
              element={
                !isWalletSetup ? (
                  <WalletSetup onSetupComplete={() => setIsWalletSetup(true)} />
                ) : !isLoggedIn ? (
                  <WalletLogin onLoginSuccess={() => setIsLoggedIn(true)} />
                ) : (
                  <Dashboard />
                )
              } 
            />
            <Route 
              path="/setup" 
              element={
                isWalletSetup ? (
                  <Navigate to="/" replace />
                ) : (
                  <WalletSetup onSetupComplete={() => setIsWalletSetup(true)} />
                )
              } 
            />
            <Route 
              path="/login" 
              element={
                !isWalletSetup ? (
                  <Navigate to="/setup" replace />
                ) : isLoggedIn ? (
                  <Navigate to="/" replace />
                ) : (
                  <WalletLogin onLoginSuccess={() => setIsLoggedIn(true)} />
                )
              } 
            />
          </Routes>
        </Router>
      </div>
    </WalletProvider>
  );
}

export default App;