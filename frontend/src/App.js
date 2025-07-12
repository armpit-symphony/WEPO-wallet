import React, { useState, useEffect } from 'react';
import UnifiedWalletModeSelector from './components/UnifiedWalletModeSelector';
import WalletLogin from './components/WalletLogin';
import WalletSetup from './components/WalletSetup';
import UnifiedWalletSetup from './components/UnifiedWalletSetup';
import UnifiedDashboard from './components/UnifiedDashboard';
import Dashboard from './components/Dashboard';
import QuantumWalletSetup from './components/QuantumWalletSetup';
import QuantumWalletLogin from './components/QuantumWalletLogin';
import { WalletProvider } from './contexts/WalletContext';
import { QuantumProvider } from './contexts/QuantumContext';
import { UnifiedWalletProvider, useUnifiedWallet } from './contexts/UnifiedWalletContext';
import './App.css';

// Main App Component with Unified Wallet
const MainApp = () => {
  const { wallet } = useUnifiedWallet();
  const [currentView, setCurrentView] = useState('mode-selector');
  const [walletMode, setWalletMode] = useState('unified'); // 'unified', 'quantum', 'legacy'

  useEffect(() => {
    // Check if user has existing wallet sessions
    const currentUser = localStorage.getItem('wepo_current_user');
    const quantumSession = sessionStorage.getItem('wepo_quantum_session_active');
    const legacySession = sessionStorage.getItem('wepo_current_wallet');

    if (wallet) {
      setCurrentView('dashboard');
    } else if (currentUser) {
      setCurrentView('login');
      setWalletMode('unified');
    } else if (quantumSession) {
      setCurrentView('quantum-login');
      setWalletMode('quantum');
    } else if (legacySession) {
      setCurrentView('login');
      setWalletMode('legacy');
    }
  }, [wallet]);

  const renderCurrentView = () => {
    switch (currentView) {
      case 'mode-selector':
        return (
          <UnifiedWalletModeSelector
            onModeSelect={(mode) => {
              setWalletMode(mode);
              setCurrentView(mode === 'quantum' ? 'quantum-setup' : 'setup');
            }}
            onLoginSelect={(mode) => {
              setWalletMode(mode);
              setCurrentView(mode === 'quantum' ? 'quantum-login' : 'login');
            }}
          />
        );

      case 'setup':
        if (walletMode === 'unified') {
          return (
            <UnifiedWalletSetup
              onWalletCreated={() => setCurrentView('dashboard')}
              onBack={() => setCurrentView('mode-selector')}
            />
          );
        } else {
          return (
            <WalletSetup
              onWalletCreated={() => setCurrentView('dashboard')}
              onBack={() => setCurrentView('mode-selector')}
            />
          );
        }

      case 'login':
        return (
          <WalletLogin
            onWalletLoaded={() => setCurrentView('dashboard')}
            onBack={() => setCurrentView('mode-selector')}
          />
        );

      case 'quantum-setup':
        return (
          <QuantumWalletSetup
            onWalletCreated={() => setCurrentView('quantum-dashboard')}
            onBack={() => setCurrentView('mode-selector')}
          />
        );

      case 'quantum-login':
        return (
          <QuantumWalletLogin
            onWalletLoaded={() => setCurrentView('quantum-dashboard')}
            onBack={() => setCurrentView('mode-selector')}
          />
        );

      case 'dashboard':
        return <UnifiedDashboard />;

      case 'quantum-dashboard':
        // For backward compatibility, still use the old quantum dashboard
        return <Dashboard />;

      default:
        return (
          <UnifiedWalletModeSelector
            onModeSelect={(mode) => {
              setWalletMode(mode);
              setCurrentView(mode === 'quantum' ? 'quantum-setup' : 'setup');
            }}
            onLoginSelect={(mode) => {
              setWalletMode(mode);
              setCurrentView(mode === 'quantum' ? 'quantum-login' : 'login');
            }}
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
        <QuantumProvider>
          <UnifiedWalletProvider>
            <MainApp />
          </UnifiedWalletProvider>
        </QuantumProvider>
      </WalletProvider>
    </div>
  );
}

export default App;