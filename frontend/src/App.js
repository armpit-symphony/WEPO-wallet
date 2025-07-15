import React, { useState, useEffect } from 'react';
import WalletLogin from './components/WalletLogin';
import WalletSetup from './components/WalletSetup';
import Dashboard from './components/Dashboard';
import { WalletProvider } from './contexts/WalletContext';
import './App.css';

// Single Wallet App with Quantum Vault
const MainApp = () => {
  const [currentView, setCurrentView] = useState('setup');

  useEffect(() => {
    // Check if user has existing wallet session
    const sessionActive = sessionStorage.getItem('wepo_session_active');
    const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
    const walletExists = localStorage.getItem('wepo_wallet_exists');
    
    if (sessionActive && sessionWallet) {
      // User has active session - go directly to dashboard
      setCurrentView('dashboard');
    } else if (walletExists) {
      // User has wallet but no active session - go to login
      setCurrentView('login');
    }
    // Otherwise stay on setup
  }, []);

  const renderCurrentView = () => {
    switch (currentView) {
      case 'setup':
        return (
          <WalletSetup
            onWalletCreated={() => setCurrentView('dashboard')}
            onLoginRedirect={() => setCurrentView('login')}
          />
        );

      case 'login':
        return (
          <WalletLogin
            onWalletLoaded={() => setCurrentView('dashboard')}
            onCreateNew={() => setCurrentView('setup')}
          />
        );

      case 'dashboard':
        return <Dashboard onLogout={() => setCurrentView('setup')} />;

      default:
        return (
          <WalletSetup
            onWalletCreated={() => setCurrentView('dashboard')}
            onLoginRedirect={() => setCurrentView('login')}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900/20 to-gray-900">
      {renderCurrentView()}
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <WalletProvider>
        <MainApp />
      </WalletProvider>
    </div>
  );
}

export default App;