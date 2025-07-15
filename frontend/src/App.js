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
    const currentUser = localStorage.getItem('wepo_current_user');
    const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
    
    if (currentUser || sessionWallet) {
      setCurrentView('login');
    }
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