import React, { useState, useEffect } from 'react';
import { 
  Eye, 
  EyeOff, 
  Send, 
  Download, 
  ArrowRightLeft,
  Bitcoin,
  Coins,
  TrendingUp,
  Clock,
  Copy,
  QrCode,
  RefreshCw,
  Package,
  Pickaxe,
  MessageCircle,
  Settings
} from 'lucide-react';
import { useUnifiedWallet } from '../contexts/UnifiedWalletContext';
import { formatAddressForDisplay, isBitcoinAddress, isWepoAddress } from '../utils/addressUtils';

// Import existing components
import SendWepo from './SendWepo';
import ReceiveWepo from './ReceiveWepo';
import QuantumMessaging from './QuantumMessaging';
import RWADashboard from './RWADashboard';
import CommunityMining from './CommunityMining';
import SettingsPanel from './SettingsPanel';
import EnhancedDEX from './EnhancedDEX';

const UnifiedDashboard = () => {
  const {
    wallet,
    wepoBalance,
    btcBalance,
    wepoTransactions,
    btcTransactions,
    loadWalletBalances,
    swapCurrencies,
    isLoading
  } = useUnifiedWallet();

  const [activeTab, setActiveTab] = useState('dashboard');
  const [showBalances, setShowBalances] = useState(true);
  const [miningMode, setMiningMode] = useState('genesis');
  const [showSwapModal, setShowSwapModal] = useState(false);
  const [swapDirection, setSwapDirection] = useState('BTC_TO_WEPO'); // BTC_TO_WEPO or WEPO_TO_BTC
  const [swapAmount, setSwapAmount] = useState('');
  const [exchangeRate, setExchangeRate] = useState(1.007);

  // Load exchange rate
  useEffect(() => {
    const loadExchangeRate = async () => {
      try {
        const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
        const response = await fetch(`${backendUrl}/api/swap/rate`);
        if (response.ok) {
          const data = await response.json();
          setExchangeRate(data.btc_to_wepo || 1.007);
        }
      } catch (error) {
        console.error('Failed to load exchange rate:', error);
      }
    };

    loadExchangeRate();
    const interval = setInterval(loadExchangeRate, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  // Check mining mode
  useEffect(() => {
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

    checkMiningMode();
  }, []);

  const handleSwap = async () => {
    try {
      const amount = parseFloat(swapAmount);
      if (amount <= 0) {
        alert('Please enter a valid amount');
        return;
      }

      const [fromCurrency, toCurrency] = swapDirection.split('_TO_');
      
      await swapCurrencies(fromCurrency, toCurrency, amount);
      
      setShowSwapModal(false);
      setSwapAmount('');
      alert(`Successfully swapped ${amount} ${fromCurrency} for ${toCurrency}`);
    } catch (error) {
      alert(`Swap failed: ${error.message}`);
    }
  };

  const calculateSwapOutput = () => {
    const amount = parseFloat(swapAmount) || 0;
    if (swapDirection === 'BTC_TO_WEPO') {
      return (amount * exchangeRate).toFixed(6);
    } else {
      return (amount / exchangeRate).toFixed(8);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  const refreshBalances = () => {
    if (wallet) {
      loadWalletBalances(wallet);
    }
  };

  // Tab content rendering
  const renderTabContent = () => {
    switch (activeTab) {
      case 'send':
        return <SendWepo onBack={() => setActiveTab('dashboard')} />;
      case 'receive':
        return <ReceiveWepo onBack={() => setActiveTab('dashboard')} />;
      case 'messaging':
        return <QuantumMessaging onBack={() => setActiveTab('dashboard')} />;
      case 'rwa':
        return <RWADashboard onBack={() => setActiveTab('dashboard')} />;
      case 'mining':
        return <CommunityMining onBack={() => setActiveTab('dashboard')} miningMode={miningMode} />;
      case 'dex':
        return <EnhancedDEX onBack={() => setActiveTab('dashboard')} />;
      case 'settings':
        return <SettingsPanel onBack={() => setActiveTab('dashboard')} />;
      default:
        return renderDashboard();
    }
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Unified Wallet</h1>
          <p className="text-gray-400">Bitcoin + WEPO in one wallet</p>
        </div>
        <button
          onClick={refreshBalances}
          className="p-2 text-gray-400 hover:text-white transition-colors"
          disabled={isLoading}
        >
          <RefreshCw className={`h-5 w-5 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Balance Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Bitcoin Balance */}
        <div className="bg-gradient-to-r from-orange-900/30 to-yellow-900/30 border border-orange-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Bitcoin className="h-8 w-8 text-orange-400" />
              <div>
                <h3 className="text-white font-semibold">Bitcoin</h3>
                <p className="text-sm text-gray-300">BTC Balance</p>
              </div>
            </div>
            <button
              onClick={() => setShowBalances(!showBalances)}
              className="text-gray-400 hover:text-white"
            >
              {showBalances ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          
          <div className="space-y-2">
            <div className="text-2xl font-bold text-orange-400">
              {showBalances ? `${btcBalance.toFixed(8)} BTC` : '••••••••'}
            </div>
            <div className="text-sm text-gray-400">
              Address: {formatAddressForDisplay(wallet?.btc?.address || '', 8, 6)}
              <button
                onClick={() => copyToClipboard(wallet?.btc?.address || '')}
                className="ml-2 text-orange-400 hover:text-orange-300"
              >
                <Copy className="h-3 w-3 inline" />
              </button>
            </div>
          </div>
        </div>

        {/* WEPO Balance */}
        <div className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Coins className="h-8 w-8 text-purple-400" />
              <div>
                <h3 className="text-white font-semibold">WEPO</h3>
                <p className="text-sm text-gray-300">WEPO Balance</p>
              </div>
            </div>
            <button
              onClick={() => setShowBalances(!showBalances)}
              className="text-gray-400 hover:text-white"
            >
              {showBalances ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          
          <div className="space-y-2">
            <div className="text-2xl font-bold text-purple-400">
              {showBalances ? `${wepoBalance.toFixed(4)} WEPO` : '••••••••'}
            </div>
            <div className="text-sm text-gray-400">
              Address: {formatAddressForDisplay(wallet?.wepo?.address || '', 8, 6)}
              <button
                onClick={() => copyToClipboard(wallet?.wepo?.address || '')}
                className="ml-2 text-purple-400 hover:text-purple-300"
              >
                <Copy className="h-3 w-3 inline" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Swap */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <ArrowRightLeft className="h-6 w-6 text-green-400" />
            <div>
              <h3 className="text-white font-semibold">Quick Swap</h3>
              <p className="text-sm text-gray-400">Instant BTC ↔ WEPO exchange</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-green-400 font-semibold">1 BTC = {exchangeRate} WEPO</div>
            <div className="text-xs text-gray-400">Live rate</div>
          </div>
        </div>
        
        <button
          onClick={() => setShowSwapModal(true)}
          className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-medium transition-colors"
        >
          Open Swap Interface
        </button>
      </div>

      {/* Action Buttons */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <button 
          onClick={() => setActiveTab('send')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200"
        >
          <Send className="h-6 w-6 text-blue-400 mx-auto mb-2" />
          <span className="text-white font-medium">Send</span>
        </button>
        
        <button 
          onClick={() => setActiveTab('receive')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200"
        >
          <Download className="h-6 w-6 text-green-400 mx-auto mb-2" />
          <span className="text-white font-medium">Receive</span>
        </button>
        
        <button 
          onClick={() => setActiveTab('messaging')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 relative"
        >
          <MessageCircle className="h-6 w-6 text-cyan-400 mx-auto mb-2" />
          <span className="text-white font-medium">Messages</span>
          <div className="absolute -top-1 -right-1 bg-cyan-500 text-white text-xs px-2 py-1 rounded-full">
            NEW
          </div>
        </button>
        
        <button 
          onClick={() => setActiveTab('mining')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 relative"
        >
          <Pickaxe className="h-6 w-6 text-yellow-400 mx-auto mb-2" />
          <span className="text-white font-medium">
            {miningMode === 'genesis' ? '🎄 Genesis Mining' : '⚡ PoW Mining'}
          </span>
          {miningMode === 'genesis' && (
            <div className="absolute -top-1 -right-1 bg-red-500 text-white text-xs px-2 py-1 rounded-full">
              XMAS
            </div>
          )}
        </button>
      </div>

      {/* Secondary Action Buttons */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button 
          onClick={() => setActiveTab('rwa')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 relative"
        >
          <Package className="h-6 w-6 text-emerald-400 mx-auto mb-2" />
          <span className="text-white font-medium">RWA Tokens</span>
          <div className="absolute -top-1 -right-1 bg-emerald-500 text-white text-xs px-2 py-1 rounded-full">
            NEW
          </div>
        </button>
        
        <button 
          onClick={() => setActiveTab('dex')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200"
        >
          <ArrowRightLeft className="h-6 w-6 text-orange-400 mx-auto mb-2" />
          <span className="text-white font-medium">Enhanced DEX</span>
        </button>
        
        <button 
          onClick={() => setActiveTab('settings')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200"
        >
          <Settings className="h-6 w-6 text-gray-400 mx-auto mb-2" />
          <span className="text-white font-medium">Settings</span>
        </button>
      </div>

      {/* Recent Transactions */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold">Recent Transactions</h3>
          <TrendingUp className="h-5 w-5 text-purple-400" />
        </div>
        
        <div className="space-y-3">
          {[...wepoTransactions.slice(0, 3), ...btcTransactions.slice(0, 2)].length === 0 ? (
            <div className="text-center py-8">
              <Clock className="h-12 w-12 text-gray-500 mx-auto mb-4" />
              <p className="text-gray-400">No transactions yet</p>
              <p className="text-sm text-gray-500 mt-1">
                Start by receiving some BTC or WEPO
              </p>
            </div>
          ) : (
            [...wepoTransactions.slice(0, 3), ...btcTransactions.slice(0, 2)].map((tx, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                <div className="flex items-center gap-3">
                  {tx.currency === 'BTC' ? 
                    <Bitcoin className="h-5 w-5 text-orange-400" /> :
                    <Coins className="h-5 w-5 text-purple-400" />
                  }
                  <div>
                    <div className="text-white font-medium">
                      {tx.type === 'send' ? 'Sent' : 'Received'} {tx.currency || 'WEPO'}
                    </div>
                    <div className="text-sm text-gray-400">
                      {formatAddressForDisplay(tx.address, 6, 4)}
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className={`font-semibold ${
                    tx.type === 'send' ? 'text-red-400' : 'text-green-400'
                  }`}>
                    {tx.type === 'send' ? '-' : '+'}{tx.amount} {tx.currency || 'WEPO'}
                  </div>
                  <div className="text-sm text-gray-400">
                    {new Date(tx.timestamp).toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900/20 to-gray-900 text-white">
      <div className="container mx-auto px-4 py-8">
        {renderTabContent()}

        {/* Swap Modal */}
        {showSwapModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="bg-gray-800 border border-gray-600 rounded-xl p-6 w-full max-w-md mx-4">
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-white font-semibold text-lg">Instant Swap</h3>
                <button
                  onClick={() => setShowSwapModal(false)}
                  className="text-gray-400 hover:text-white"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                {/* Swap Direction */}
                <div className="flex gap-2">
                  <button
                    onClick={() => setSwapDirection('BTC_TO_WEPO')}
                    className={`flex-1 p-3 rounded-lg font-medium transition-colors ${
                      swapDirection === 'BTC_TO_WEPO' 
                        ? 'bg-orange-600 text-white' 
                        : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                    }`}
                  >
                    BTC → WEPO
                  </button>
                  <button
                    onClick={() => setSwapDirection('WEPO_TO_BTC')}
                    className={`flex-1 p-3 rounded-lg font-medium transition-colors ${
                      swapDirection === 'WEPO_TO_BTC' 
                        ? 'bg-purple-600 text-white' 
                        : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                    }`}
                  >
                    WEPO → BTC
                  </button>
                </div>
                
                {/* Amount Input */}
                <div>
                  <label className="block text-sm text-gray-400 mb-2">
                    Amount ({swapDirection.split('_')[0]})
                  </label>
                  <input
                    type="number"
                    value={swapAmount}
                    onChange={(e) => setSwapAmount(e.target.value)}
                    placeholder="0.00000000"
                    className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-purple-500 focus:outline-none"
                  />
                </div>
                
                {/* Output Display */}
                <div className="bg-gray-700/50 p-3 rounded-lg">
                  <div className="text-sm text-gray-400 mb-1">You will receive:</div>
                  <div className="text-lg font-semibold text-white">
                    {calculateSwapOutput()} {swapDirection.split('_TO_')[1]}
                  </div>
                </div>
                
                {/* Exchange Rate */}
                <div className="text-center text-sm text-gray-400">
                  Rate: 1 BTC = {exchangeRate} WEPO
                </div>
                
                {/* Swap Button */}
                <button
                  onClick={handleSwap}
                  disabled={!swapAmount || parseFloat(swapAmount) <= 0 || isLoading}
                  className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white py-3 rounded-lg font-medium transition-colors"
                >
                  {isLoading ? 'Swapping...' : 'Execute Swap'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UnifiedDashboard;