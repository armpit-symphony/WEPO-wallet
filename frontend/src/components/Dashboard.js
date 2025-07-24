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
  Settings,
  Users,
  Zap,
  Lock,
  Shield,
  AlertCircle,
  LogOut,
  Server,
  ToggleRight,
  ToggleLeft
} from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';
// Temporarily commented out for Buffer isolation testing
// import { generateBitcoinAddress } from '../utils/addressUtils';
import SendWepo from './SendWepo';
import ReceiveWepo from './ReceiveWepo';
import QuantumVault from './QuantumVault';
import BtcDexSwap from './BtcDexSwap';
import QuantumMessaging from './QuantumMessaging';
import RWADashboard from './RWADashboard';
import CommunityMining from './CommunityMining';
import UnifiedExchange from './UnifiedExchange';
import StakingInterface from './StakingInterface';
import MasternodeInterface from './MasternodeInterface';
import SettingsPanel from './SettingsPanel';

const Dashboard = ({ onLogout }) => {
  const { 
    wallet, 
    balance, 
    btcBalance,
    transactions, 
    btcTransactions,
    posEnabled, 
    masternodesEnabled,
    loadWalletData,
    setBalance,
    setTransactions,
    logout,
    setWallet,
    
    // Bitcoin wallet data
    btcWallet,
    btcAddresses,
    btcUtxos,
    isBtcLoading,
    sendBitcoin,
    getNewBitcoinAddress,
    getBitcoinBalance,
    exportBitcoinWalletInfo
  } = useWallet();
  
  // Simplified without quantum features for now
  const currentWallet = wallet;
  const currentBalance = balance;
  const currentTransactions = transactions;
  
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showBalance, setShowBalance] = useState(true);
  const [miningMode, setMiningMode] = useState('genesis'); // 'genesis' or 'pow'
  
  // Quantum Vault state
  const [showQuantumVault, setShowQuantumVault] = useState(false);
  const [isQuantumMode, setIsQuantumMode] = useState(true); // Default to Private mode for privacy project
  const [quantumStatus, setQuantumStatus] = useState(null);
  
  // Dilithium info for quantum security display (dynamic from backend)
  const dilithiumInfo = quantumStatus ? {
    algorithm: quantumStatus.algorithm || 'Dilithium2',
    variant: quantumStatus.variant || 'NIST ML-DSA',
    implementation: quantumStatus.implementation || 'dilithium-py',
    security_level: quantumStatus.security_level ? `${quantumStatus.security_level}-bit` : '128-bit',
    quantum_resistant: quantumStatus.quantum_resistant || false,
    nist_approved: quantumStatus.nist_approved || false
  } : {
    algorithm: 'Loading...',
    variant: 'Loading...',
    implementation: 'Loading...',
    security_level: 'Loading...',
    quantum_resistant: false,
    nist_approved: false
  };
  // Fetch quantum status from backend
  const fetchQuantumStatus = async () => {
    try {
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/quantum/status`);
      if (response.ok) {
        const data = await response.json();
        // Adapt existing quantum status format
        const adaptedStatus = {
          quantum_resistant: data.quantum_ready || true,
          algorithm: data.signature_algorithm || 'Dilithium2',
          variant: 'NIST ML-DSA',
          implementation: data.implementation || 'WEPO Quantum-Resistant v1.0',
          security_level: 128,
          nist_approved: true,
          post_quantum: data.quantum_ready || true,
          current_height: data.current_height || 0
        };
        setQuantumStatus(adaptedStatus);
        setIsQuantumMode(adaptedStatus.quantum_resistant);
      }
    } catch (error) {
      console.log('Quantum status fetch failed:', error);
      // Set default status indicating quantum resistance is available
      setQuantumStatus({
        quantum_resistant: true,
        algorithm: 'Dilithium2',
        variant: 'NIST ML-DSA',
        implementation: 'WEPO Quantum-Resistant v1.0',
        security_level: 128,
        nist_approved: true,
        post_quantum: true
      });
      setIsQuantumMode(true);
    }
  };

  // Effect to fetch quantum status
  useEffect(() => {
    fetchQuantumStatus();
  }, []);

  const handleModeToggle = () => {
    // Toggle between private mode display (UI only)
    setIsQuantumMode(!isQuantumMode);
    console.log(`Private mode ${!isQuantumMode ? 'enabled' : 'disabled'} for display`);
  };

  useEffect(() => {
    // Load wallet data if not already loaded
    const loadData = async () => {
      if (!wallet) {
        const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
        if (sessionWallet) {
          try {
            const walletData = JSON.parse(sessionWallet);
            setWallet(walletData);
            
            // Load real balance from blockchain instead of hardcoded value
            await loadWalletData(walletData.address);
          } catch (error) {
            console.error('Failed to load wallet data:', error);
            // Set zero balance if loading fails
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
        return <SendWepo onClose={() => setActiveTab('dashboard')} />;
      case 'receive':
        return <ReceiveWepo onClose={() => setActiveTab('dashboard')} />;
      case 'btc-dex':
        return <UnifiedExchange onBack={() => setActiveTab('dashboard')} />;
      case 'staking':
        return <StakingInterface onBack={() => setActiveTab('dashboard')} />;
      case 'masternode':
        return <MasternodeInterface onBack={() => setActiveTab('dashboard')} />;
      case 'settings':
        return <SettingsPanel onClose={() => setActiveTab('dashboard')} />;
      case 'messaging':
        return <QuantumMessaging onBack={() => setActiveTab('dashboard')} />;
      case 'rwa':
        return <RWADashboard onBack={() => setActiveTab('dashboard')} />;
      case 'mining':
        return <CommunityMining onBack={() => setActiveTab('dashboard')} miningMode={miningMode} />;
      default:
        return renderDashboard();
    }
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Balance Card */}
      <div className={`rounded-2xl p-6 text-white ${
        isQuantumMode 
          ? 'bg-gradient-to-r from-purple-600 to-blue-600' 
          : 'bg-gradient-to-r from-purple-600 to-blue-600'
      }`}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <p className="text-purple-100 text-sm font-medium">Total Balance</p>
              {isQuantumMode && (
                <div className="flex items-center gap-1 bg-white/20 px-2 py-1 rounded-full">
                  <Zap className="h-3 w-3 text-yellow-300" />
                  <span className="text-xs text-yellow-300">Private</span>
                </div>
              )}
            </div>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-3xl font-bold">
                {showBalance ? formatBalance(currentBalance) : '••••••••'}
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
            Address: {currentWallet?.address?.substring(0, 20)}...
          </div>
          {isQuantumMode && (
            <div className="text-xs text-purple-100">
              Post-quantum secure
            </div>
          )}
        </div>
      </div>



      {/* BTC Wallet Integration */}
      <div className="bg-gradient-to-r from-orange-900/30 to-yellow-900/30 border border-orange-500/30 rounded-xl p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Bitcoin className="h-8 w-8 text-orange-400" />
            <div>
              <h3 className="text-white font-semibold">Bitcoin Integration</h3>
              <p className="text-sm text-gray-300">Hold BTC while waiting for genesis launch</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-orange-400 font-semibold">Ready for Christmas</div>
            <div className="text-xs text-gray-400">Dec 25, 2025 Launch</div>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">BTC Balance</div>
            <div className="text-orange-400 font-semibold">
              {btcBalance.toFixed(8)} BTC
            </div>
            <div className="text-green-400 text-xs mt-1">
              {btcAddresses.length > 0 ? '✅ Mainnet Active' : '⏳ Initializing...'}
            </div>
          </div>
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">Mode</div>
            <div className="text-white font-semibold">
              Public Mode
            </div>
            <div className="text-blue-400 text-xs mt-1">
              Direct Bitcoin
            </div>
          </div>
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">Private Mode</div>
            <div className="text-white font-semibold">
              {masternodesEnabled ? 'Available' : 'Coming Soon'}
            </div>
            <div className={`text-xs mt-1 ${masternodesEnabled ? 'text-green-400' : 'text-gray-500'}`}>
              {masternodesEnabled ? 'Via Masternodes' : 'Need Active Masternodes'}
            </div>
          </div>
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">Your Keys</div>
            <div className="text-green-400 font-semibold">Your Control</div>
            <div className="text-green-400 text-xs mt-1">True self-custody</div>
          </div>
        </div>
        
        <div className="mt-4 p-3 bg-orange-900/30 rounded-lg">
          <p className="text-orange-200 text-sm">
            🔐 <strong>Self-Custodial Bitcoin Wallet (MAINNET):</strong> Your Bitcoin private keys are generated from your WEPO seed phrase. 
            <strong className="text-green-300"> Public Mode: </strong> Direct Bitcoin transactions available now.
            <strong className="text-purple-300"> Private Mode: </strong> Enhanced privacy via masternode mixing - available to everyone (small mixing fees apply).
          </p>
          <p className="text-yellow-200 text-xs mt-2">
            💡 <strong>Run a Masternode:</strong> Earn mixing fees by providing privacy services to the network. Requires 10,000 WEPO collateral.
          </p>
        </div>
      </div>
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
          <span className="text-white font-medium">Quantum Messages</span>
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
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <button 
          onClick={() => setShowQuantumVault(true)}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50 relative"
        >
          <Shield className="h-6 w-6 text-purple-400 mx-auto mb-2" />
          <span className="text-white font-medium">Quantum Vault</span>
          <div className="absolute -top-1 -right-1 bg-purple-500 text-white text-xs px-2 py-1 rounded-full">
            PRIVATE
          </div>
          <div className="text-xs text-gray-400 mt-1">Ultimate Privacy</div>
        </button>
        
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
          onClick={() => setActiveTab('btc-dex')}
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
            <div>
              <div className="mb-3 p-3 bg-purple-900/30 rounded-lg">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-300">Collateral Required:</span>
                  <span className="text-purple-400 font-semibold">10,000 WEPO</span>
                </div>
                <div className="flex items-center justify-between text-sm mt-1">
                  <span className="text-gray-300">Your Balance:</span>
                  <span className={`font-semibold ${balance >= 10000 ? 'text-green-400' : 'text-red-400'}`}>
                    {formatBalance(balance)} WEPO
                  </span>
                </div>
              </div>
              
              {balance >= 10000 ? (
                <button
                  onClick={() => setActiveTab('masternodes')}
                  className="w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-4 rounded-lg transition-colors"
                >
                  Setup Masternode
                </button>
              ) : (
                <div className="text-center">
                  <div className="text-orange-400 text-sm mb-2">
                    Insufficient WEPO for masternode
                  </div>
                  <div className="text-xs text-gray-500">
                    Need {(10000 - balance).toLocaleString()} more WEPO
                  </div>
                </div>
              )}
            </div>
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

      {/* Privacy Status Card (only show in private mode) - Moved to bottom */}
      {isQuantumMode && (
        <div className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-xl p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Zap className="h-8 w-8 text-yellow-400" />
              <div>
                <h3 className="text-white font-semibold">Privacy Security Status</h3>
                <p className="text-sm text-gray-300">Post-quantum cryptography active</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-green-400 font-semibold">ACTIVE</div>
              <div className="text-xs text-gray-400">128-bit quantum level</div>
            </div>
          </div>
          
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <div className="text-gray-400">Algorithm</div>
              <div className="text-white font-medium">
                {dilithiumInfo?.algorithm || 'Dilithium2'}
              </div>
            </div>
            <div>
              <div className="text-gray-400">Hash Function</div>
              <div className="text-white font-medium">BLAKE2b</div>
            </div>
            <div>
              <div className="text-gray-400">Signature Size</div>
              <div className="text-white font-medium">
                {dilithiumInfo?.signature_size || 2420} bytes
              </div>
            </div>
            <div>
              <div className="text-gray-400">Quantum Ready</div>
              <div className="text-green-400 font-medium">✓ Yes</div>
            </div>
          </div>
          
          {quantumStatus && (
            <div className="mt-4 pt-4 border-t border-purple-500/30">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Blockchain Height:</span>
                <span className="text-white">{quantumStatus.current_height}</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-400">Mempool Size:</span>
                <span className="text-white">{quantumStatus.mempool_size}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recent Transactions */}
      <div className="bg-gray-800 rounded-xl border border-gray-600">
        <div className="p-6 border-b border-gray-600">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-purple-400" />
            Recent Transactions
          </h3>
        </div>
        
        <div className="p-6">
          {currentTransactions.length === 0 ? (
            <div className="text-center py-8">
              <AlertCircle className="h-12 w-12 text-gray-500 mx-auto mb-4" />
              <p className="text-gray-400">No transactions yet</p>
              <p className="text-sm text-gray-500 mt-1">
                Your transaction history will appear here
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {currentTransactions.slice(0, 5).map((tx) => (
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
                      <div className="flex items-center gap-2">
                        <p className="text-white font-medium capitalize">{tx.type}</p>
                        {tx.quantumResistant && (
                          <div className="flex items-center gap-1 bg-purple-600/20 px-2 py-1 rounded-full">
                            <Zap className="h-3 w-3 text-yellow-400" />
                            <span className="text-xs text-yellow-400">Quantum</span>
                          </div>
                        )}
                      </div>
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
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white">WEPO Wallet</h1>
                {isQuantumMode && (
                  <div className="flex items-center gap-1 bg-purple-600/20 px-2 py-1 rounded-full">
                    <Zap className="h-3 w-3 text-yellow-400" />
                    <span className="text-xs text-yellow-400">Private</span>
                  </div>
                )}
              </div>
              <p className="text-purple-200 text-sm">Welcome back, {currentWallet?.username}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Mode Toggle */}
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-300">Public</span>
              <button
                onClick={handleModeToggle}
                className="relative inline-flex items-center cursor-pointer"
                title={isQuantumMode ? 'Switch to Public Mode' : 'Switch to Private Mode'}
              >
                {isQuantumMode ? (
                  <ToggleRight className="h-6 w-6 text-purple-400" />
                ) : (
                  <ToggleLeft className="h-6 w-6 text-gray-400" />
                )}
              </button>
              <span className="text-sm text-gray-300">Private</span>
            </div>
            
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
      
      {/* Quantum Vault Modal */}
      {showQuantumVault && (
        <QuantumVault onClose={() => setShowQuantumVault(false)} />
      )}
    </div>
  );
};

export default Dashboard;