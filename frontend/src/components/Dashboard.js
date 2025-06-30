import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Send, 
  Download, 
  Settings, 
  LogOut, 
  Eye, 
  EyeOff,
  Coins,
  TrendingUp,
  Lock,
  Server,
  ArrowRightLeft,
  AlertCircle,
  Clock
} from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';
import SendWepo from './SendWepo';
import ReceiveWepo from './ReceiveWepo';
import BtcDexSwap from './BtcDexSwap';
import StakingInterface from './StakingInterface';
import MasternodeInterface from './MasternodeInterface';
import SettingsPanel from './SettingsPanel';

const Dashboard = () => {
  const { 
    wallet, 
    balance, 
    transactions, 
    posEnabled, 
    masternodesEnabled,
    logout,
    setWallet,
    setBalance,
    setTransactions
  } = useWallet();
  
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showBalance, setShowBalance] = useState(true);

  useEffect(() => {
    // Load wallet data if not already loaded
    if (!wallet) {
      const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
      if (sessionWallet) {
        try {
          const walletData = JSON.parse(sessionWallet);
          setWallet(walletData);
          setBalance(walletData.balance || 1000.5);
          
          // Mock transactions
          setTransactions([
            {
              id: '1',
              type: 'receive',
              amount: 100,
              from: 'wepo1abc...def',
              to: walletData.address,
              timestamp: new Date().toISOString(),
              status: 'confirmed'
            },
            {
              id: '2',
              type: 'send',
              amount: 50,
              from: walletData.address,
              to: 'wepo1xyz...123',
              timestamp: new Date(Date.now() - 86400000).toISOString(),
              status: 'confirmed'
            }
          ]);
        } catch (error) {
          console.error('Failed to load wallet data:', error);
        }
      }
    }
  }, [wallet, setWallet, setBalance, setTransactions]);

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
    switch (activeTab) {
      case 'send':
        return <SendWepo onClose={() => setActiveTab('dashboard')} />;
      case 'receive':
        return <ReceiveWepo onClose={() => setActiveTab('dashboard')} />;
      case 'dex':
        return <BtcDexSwap onClose={() => setActiveTab('dashboard')} />;
      case 'staking':
        return <StakingInterface onClose={() => setActiveTab('dashboard')} />;
      case 'masternodes':
        return <MasternodeInterface onClose={() => setActiveTab('dashboard')} />;
      case 'settings':
        return <SettingsPanel onClose={() => setActiveTab('dashboard')} />;
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
            <p className="text-purple-100 text-sm font-medium">Total Balance</p>
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
          <Shield className="h-12 w-12 text-purple-200" />
        </div>
        
        <div className="text-sm text-purple-100">
          Address: {wallet?.address?.substring(0, 20)}...
        </div>
      </div>

      {/* Action Buttons */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <button
          onClick={() => setActiveTab('send')}
          className="bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-xl p-4 text-center transition-colors group"
        >
          <Send className="h-8 w-8 text-purple-400 mx-auto mb-2 group-hover:text-purple-300" />
          <span className="text-white font-medium">Send</span>
        </button>
        
        <button
          onClick={() => setActiveTab('receive')}
          className="bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-xl p-4 text-center transition-colors group"
        >
          <Download className="h-8 w-8 text-green-400 mx-auto mb-2 group-hover:text-green-300" />
          <span className="text-white font-medium">Receive</span>
        </button>
        
        <button
          onClick={() => setActiveTab('dex')}
          className="bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-xl p-4 text-center transition-colors group"
        >
          <ArrowRightLeft className="h-8 w-8 text-blue-400 mx-auto mb-2 group-hover:text-blue-300" />
          <span className="text-white font-medium">BTC DEX</span>
        </button>
        
        <button
          onClick={() => setActiveTab('settings')}
          className="bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-xl p-4 text-center transition-colors group"
        >
          <Settings className="h-8 w-8 text-gray-400 mx-auto mb-2 group-hover:text-gray-300" />
          <span className="text-white font-medium">Settings</span>
        </button>
      </div>

      {/* PoS and Masternode Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className={`bg-gray-800 border rounded-xl p-6 ${posEnabled ? 'border-green-500/30' : 'border-gray-600'}`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Coins className={`h-8 w-8 ${posEnabled ? 'text-green-400' : 'text-gray-500'}`} />
              <div>
                <h3 className="text-white font-semibold">Proof of Stake</h3>
                <p className="text-sm text-gray-400">Earn by staking WEPO</p>
              </div>
            </div>
            {!posEnabled && <Lock className="h-5 w-5 text-gray-500" />}
          </div>
          
          {posEnabled ? (
            <button
              onClick={() => setActiveTab('staking')}
              className="w-full bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Start Staking
            </button>
          ) : (
            <div className="text-center">
              <div className="flex items-center justify-center gap-2 text-gray-400 mb-2">
                <Clock size={16} />
                <span className="text-sm">Unlocks in 18 months</span>
              </div>
              <div className="text-xs text-gray-500">
                After first PoW block is mined
              </div>
            </div>
          )}
        </div>

        <div className={`bg-gray-800 border rounded-xl p-6 ${masternodesEnabled ? 'border-purple-500/30' : 'border-gray-600'}`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Server className={`h-8 w-8 ${masternodesEnabled ? 'text-purple-400' : 'text-gray-500'}`} />
              <div>
                <h3 className="text-white font-semibold">Masternodes</h3>
                <p className="text-sm text-gray-400">Run network infrastructure</p>
              </div>
            </div>
            {!masternodesEnabled && <Lock className="h-5 w-5 text-gray-500" />}
          </div>
          
          {masternodesEnabled ? (
            <button
              onClick={() => setActiveTab('masternodes')}
              className="w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
            >
              Setup Masternode
            </button>
          ) : (
            <div className="text-center">
              <div className="flex items-center justify-center gap-2 text-gray-400 mb-2">
                <Clock size={16} />
                <span className="text-sm">Unlocks in 18 months</span>
              </div>
              <div className="text-xs text-gray-500">
                After first PoW block is mined
              </div>
            </div>
          )}
        </div>
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
          
          <button
            onClick={logout}
            className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors"
          >
            <LogOut size={16} />
            Logout
          </button>
        </div>

        {/* Main Content */}
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-purple-500/20 p-6">
          {renderTabContent()}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;