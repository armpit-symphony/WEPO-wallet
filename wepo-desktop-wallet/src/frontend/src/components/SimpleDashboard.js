import React, { useState, useEffect } from 'react';
import { 
  Eye, 
  EyeOff, 
  Send, 
  Download, 
  ArrowRightLeft,
  Shield,
  LogOut,
  AlertCircle,
  TrendingUp,
  Package,
  Pickaxe,
  MessageCircle,
  Settings
} from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';
import SendWepo from './SendWepo';
import ReceiveWepo from './ReceiveWepo';
import UnifiedExchange from './UnifiedExchange';
import RWADashboard from './RWADashboard';
import CommunityMining from './CommunityMining';
import QuantumMessaging from './QuantumMessaging';
import SettingsPanel from './SettingsPanel';

const SimpleDashboard = ({ onLogout }) => {
  const { 
    wallet, 
    balance, 
    transactions, 
    loadWalletData,
    setBalance,
    setTransactions,
    logout,
    setWallet
  } = useWallet();
  
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showBalance, setShowBalance] = useState(true);
  const [miningMode, setMiningMode] = useState('genesis');

  useEffect(() => {
    // Load wallet data if not already loaded
    const loadData = async () => {
      if (!wallet) {
        const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
        if (sessionWallet) {
          try {
            const walletData = JSON.parse(sessionWallet);
            setWallet(walletData);
            
            // Load real balance from blockchain
            await loadWalletData(walletData.address);
          } catch (error) {
            console.error('Failed to load wallet data:', error);
            setBalance(0);
            setTransactions([]);
          }
        }
      }
    };

    // Check mining mode based on genesis status
    const checkMiningMode = async () => {
      try {
        const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
        const response = await fetch(`${backendUrl}/api/mining/status`);
        if (response.ok) {
          const data = await response.json();
          if (data.genesis_status === 'found') {
            setMiningMode('pow');
          }
        }
      } catch (error) {
        console.log('Mining status check failed, defaulting to genesis mode');
      }
    };

    loadData();
    checkMiningMode();
  }, [wallet, setWallet, setBalance, setTransactions, loadWalletData]);

  const handleLogout = () => {
    logout();
  };

  const formatBalance = (amount) => {
    return new Intl.NumberFormat('en-US', {
      minimumFractionDigits: 4,
      maximumFractionDigits: 4,
    }).format(amount);
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const renderTabContent = () => {
    switch(activeTab) {
      case 'send':
        return <SendWepo onBack={() => setActiveTab('dashboard')} />;
      case 'receive':
        return <ReceiveWepo onBack={() => setActiveTab('dashboard')} />;
      case 'unified-exchange':
        return <UnifiedExchange onBack={() => setActiveTab('dashboard')} />;
      case 'rwa':
        return <RWADashboard onBack={() => setActiveTab('dashboard')} />;
      case 'mining':
        return <CommunityMining onBack={() => setActiveTab('dashboard')} miningMode={miningMode} />;
      case 'messaging':
        return <QuantumMessaging onBack={() => setActiveTab('dashboard')} />;
      case 'settings':
        return <SettingsPanel onBack={() => setActiveTab('dashboard')} />;
      default:
        return renderDashboard();
    }
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Balance Card */}
      <div className="bg-gradient-to-r from-purple-600 to-blue-600 rounded-2xl p-6 text-white">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <p className="text-purple-100 text-sm font-medium">Total Balance</p>
            </div>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-3xl font-bold">
                {showBalance ? formatBalance(balance) : '••••••••'}
              </span>
              <span className="text-xl text-purple-200">WEPO</span>
              <button
                onClick={() => setShowBalance(!showBalance)}
                className="text-purple-200 hover:text-white transition-colors"
              >
                {showBalance ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>
          </div>
          <div className="text-right">
            <Shield className="h-12 w-12 text-purple-200 mb-2" />
          </div>
        </div>
        
        <div className="flex items-center justify-between">
          <div className="text-sm text-purple-100">
            Address: {wallet?.address?.substring(0, 20)}...
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <button 
          onClick={() => setActiveTab('send')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50"
        >
          <Send className="h-6 w-6 text-purple-400 mx-auto mb-2" />
          <span className="text-white font-medium">Send WEPO</span>
        </button>
        
        <button 
          onClick={() => setActiveTab('receive')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50"
        >
          <Download className="h-6 w-6 text-blue-400 mx-auto mb-2" />
          <span className="text-white font-medium">Receive WEPO</span>
        </button>
        
        <button 
          onClick={() => setActiveTab('messaging')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50 relative"
        >
          <MessageCircle className="h-6 w-6 text-green-400 mx-auto mb-2" />
          <span className="text-white font-medium">Messages</span>
          <div className="absolute -top-1 -right-1 bg-green-500 text-white text-xs px-2 py-1 rounded-full">
            NEW
          </div>
        </button>
        
        <button 
          onClick={() => setActiveTab('mining')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50 relative"
        >
          <Pickaxe className="h-6 w-6 text-yellow-400 mx-auto mb-2" />
          <span className="text-white font-medium">
            {miningMode === 'genesis' ? '🎄 Join Genesis Mining' : '⚡ Start PoW Mining'}
          </span>
          {miningMode === 'genesis' && (
            <div className="absolute -top-1 -right-1 bg-red-500 text-white text-xs px-2 py-1 rounded-full">
              XMAS
            </div>
          )}
        </button>
      </div>

      {/* Secondary Action Buttons */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <button 
          onClick={() => setActiveTab('rwa')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50 relative"
        >
          <Package className="h-6 w-6 text-emerald-400 mx-auto mb-2" />
          <span className="text-white font-medium">RWA Tokens</span>
          <div className="absolute -top-1 -right-1 bg-emerald-500 text-white text-xs px-2 py-1 rounded-full">
            NEW
          </div>
        </button>
        
        <button 
          onClick={() => setActiveTab('unified-exchange')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50"
        >
          <ArrowRightLeft className="h-6 w-6 text-orange-400 mx-auto mb-2" />
          <span className="text-white font-medium">Unified Exchange</span>
          <div className="text-xs text-gray-400 mt-1">BTC + RWA Trading</div>
        </button>
        
        <button 
          onClick={() => setActiveTab('settings')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50"
        >
          <Settings className="h-6 w-6 text-gray-400 mx-auto mb-2" />
          <span className="text-white font-medium">Settings</span>
        </button>
      </div>

      {/* Recent Transactions */}
      <div className="bg-gray-800 rounded-xl border border-gray-600">
        <div className="p-6 border-b border-gray-600">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-purple-400" />
            Recent Transactions
          </h3>
        </div>
        
        <div className="p-6">
          {transactions.length === 0 ? (
            <div className="text-center py-8">
              <AlertCircle className="h-12 w-12 text-gray-500 mx-auto mb-4" />
              <p className="text-gray-400">No transactions yet</p>
              <p className="text-sm text-gray-500 mt-1">
                Your transaction history will appear here
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {transactions.slice(0, 5).map((tx) => (
                <div key={tx.id} className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-full ${
                      tx.type === 'send' 
                        ? 'bg-red-500/20 text-red-400' 
                        : 'bg-green-500/20 text-green-400'
                    }`}>
                      {tx.type === 'send' ? <Send size={16} /> : <Download size={16} />}
                    </div>
                    <div>
                      <p className="text-white font-medium capitalize">{tx.type}</p>
                      <p className="text-sm text-gray-400">{formatDate(tx.timestamp)}</p>
                    </div>
                  </div>
                  
                  <div className="text-right">
                    <p className={`font-medium ${
                      tx.type === 'send' ? 'text-red-400' : 'text-green-400'
                    }`}>
                      {tx.type === 'send' ? '-' : '+'}{formatBalance(tx.amount)} WEPO
                    </p>
                    <p className={`text-xs ${
                      tx.status === 'confirmed' ? 'text-green-400' : 
                      tx.status === 'pending' ? 'text-yellow-400' : 'text-gray-400'
                    }`}>
                      {tx.status}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900">
      <div className="max-w-4xl mx-auto p-4">
        {/* Header */}
        <div className="flex items-center justify-between mb-8 bg-gray-800/50 backdrop-blur-sm rounded-xl p-4 border border-purple-500/20">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-purple-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">WEPO Wallet</h1>
              <p className="text-purple-200 text-sm">Welcome back, {wallet?.username}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors"
            >
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </div>

        {/* Main Content */}
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-purple-500/20 p-6">
          {renderTabContent()}
        </div>
      </div>
    </div>
  );
};

export default SimpleDashboard;