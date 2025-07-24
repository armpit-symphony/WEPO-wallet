import React, { useState, useEffect } from 'react';
import WalletLogin from './components/WalletLogin';
import WalletSetup from './components/WalletSetup';
import Dashboard from './components/Dashboard';
import { WalletProvider, useWallet } from './contexts/WalletContext';
import './App.css';

// Main App Component that handles wallet state
const MainApp = () => {
  const [currentView, setCurrentView] = useState('setup');
  const [isInitialized, setIsInitialized] = useState(false);
  const { setWallet } = useWallet();

  useEffect(() => {
    const initializeApp = async () => {
      try {
        // Check if user has existing wallet session
        const sessionActive = sessionStorage.getItem('wepo_session_active');
        const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
        const walletExists = localStorage.getItem('wepo_wallet_exists');

        if (sessionActive === 'true' && sessionWallet) {
          const wallet = JSON.parse(sessionWallet);
          setWallet(wallet);
          setCurrentView('dashboard');
        } else if (walletExists === 'true') {
          setCurrentView('login');
        } else {
          setCurrentView('setup');
        }
      } catch (error) {
        console.error('Failed to initialize app:', error);
        setCurrentView('setup');
      } finally {
        setIsInitialized(true);
      }
    };

    initializeApp();
  }, [setWallet]);

  if (!isInitialized) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-purple-900 flex items-center justify-center">
        <div className="text-white text-xl">Loading WEPO...</div>
      </div>
    );
  }

  const handleViewChange = (view) => {
    setCurrentView(view);
  };

  return (
    <div className="App">
      {currentView === 'setup' && (
        <WalletSetup 
          onWalletCreated={() => handleViewChange('dashboard')} 
          onLoginRedirect={() => handleViewChange('login')} 
        />
      )}
      {currentView === 'login' && (
        <WalletLogin 
          onSuccess={() => handleViewChange('dashboard')}
          onCreateNew={() => handleViewChange('setup')}
        />
      )}
      {currentView === 'dashboard' && (
        <Dashboard onLogout={() => handleViewChange('setup')} />
      )}
    </div>
  );
};

// Wrap the app with WalletProvider
function App() {
  return (
    <WalletProvider>
      <MainApp />
    </WalletProvider>
  );
}

export default App;