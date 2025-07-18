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
        
        console.log('🔍 App initialization check:', {
          sessionActive: !!sessionActive,
          sessionWallet: !!sessionWallet,
          walletExists: !!walletExists
        });
        
        if (sessionActive && sessionWallet) {
          // User has active session - initialize wallet context and go to dashboard
          try {
            const walletData = JSON.parse(sessionWallet);
            setWallet(walletData);
            setCurrentView('dashboard');
            console.log('✅ Restored wallet session for:', walletData.username);
          } catch (error) {
            console.error('Failed to parse session wallet:', error);
            // Clear corrupted session data
            sessionStorage.removeItem('wepo_session_active');
            sessionStorage.removeItem('wepo_current_wallet');
            if (walletExists) {
              setCurrentView('login');
            }
          }
        } else if (walletExists) {
          // User has wallet but no active session - go to login
          setCurrentView('login');
        }
        // Otherwise stay on setup
        
      } catch (error) {
        console.error('App initialization error:', error);
        setCurrentView('setup');
      } finally {
        setIsInitialized(true);
      }
    };

    initializeApp();
  }, [setWallet]);

  const handleWalletCreated = () => {
    console.log('🎉 Wallet created, transitioning to dashboard');
    // Get the wallet data from session storage and set it in context
    const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
    if (sessionWallet) {
      try {
        const walletData = JSON.parse(sessionWallet);
        setWallet(walletData);
        setCurrentView('dashboard');
        console.log('✅ Wallet context updated:', walletData.username);
      } catch (error) {
        console.error('Failed to set wallet context:', error);
      }
    }
  };

  const handleWalletLoaded = () => {
    console.log('🔑 Wallet loaded, transitioning to dashboard');
    setCurrentView('dashboard');
  };

  const handleLogout = () => {
    console.log('👋 Logout initiated');
    // Clear session data
    sessionStorage.removeItem('wepo_session_active');
    sessionStorage.removeItem('wepo_current_wallet');
    setWallet(null);
    
    // Check if wallet still exists for future login
    const walletExists = localStorage.getItem('wepo_wallet_exists');
    if (walletExists) {
      setCurrentView('login');
    } else {
      setCurrentView('setup');
    }
  };

  // Show loading while initializing
  if (!isInitialized) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900/20 to-gray-900 flex items-center justify-center">
        <div className="text-white text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-400 mx-auto mb-4"></div>
          <p>Initializing WEPO Wallet...</p>
        </div>
      </div>
    );
  }

  const renderCurrentView = () => {
    switch (currentView) {
      case 'setup':
        return (
          <WalletSetup
            onWalletCreated={handleWalletCreated}
            onLoginRedirect={() => setCurrentView('login')}
          />
        );

      case 'login':
        return (
          <WalletLogin
            onWalletLoaded={handleWalletLoaded}
            onCreateNew={() => setCurrentView('setup')}
          />
        );

      case 'dashboard':
        return <Dashboard onLogout={handleLogout} />;

      default:
        return (
          <WalletSetup
            onWalletCreated={handleWalletCreated}
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