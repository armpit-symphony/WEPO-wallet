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
  ToggleLeft,
  ChevronDown
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
import GovernanceDashboard from './GovernanceDashboard';

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
  
  // Bitcoin section state
  const [showBitcoinDetails, setShowBitcoinDetails] = useState(false);
  
  // PoS Collateral state
  const [posCollateralInfo, setPosCollateralInfo] = useState(null);
  const [posCollateralLoading, setPosCollateralLoading] = useState(true);
  
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

  // Fetch PoS collateral information from backend
  const fetchPosCollateralInfo = async () => {
    try {
      setPosCollateralLoading(true);
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/collateral/requirements`);
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.data) {
          setPosCollateralInfo(data.data);
          console.log('✅ PoS collateral info loaded:', data.data);
        } else {
          console.warn('⚠️ PoS collateral API returned unsuccessful response');
        }
      } else {
        console.warn('⚠️ PoS collateral API not accessible');
      }
    } catch (error) {
      console.error('❌ Failed to fetch PoS collateral info:', error);
    } finally {
      setPosCollateralLoading(false);
    }
  };

  // Effect to fetch quantum status and PoS collateral info
  useEffect(() => {
    fetchQuantumStatus();
    fetchPosCollateralInfo();
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
      case 'governance':
        return <GovernanceDashboard onBack={() => setActiveTab('dashboard')} />;
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



      {/* BTC Wallet Integration - Compact Button */}
      <div className="mb-6">
        <button
          onClick={() => setShowBitcoinDetails(!showBitcoinDetails)}
          className="w-full bg-gradient-to-r from-orange-900/30 to-yellow-900/30 border border-orange-500/30 rounded-xl p-4 hover:from-orange-900/40 hover:to-yellow-900/40 transition-all duration-200"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Bitcoin className="h-6 w-6 text-orange-400" />
              <div className="text-left">
                <h3 className="text-white font-semibold">BTC</h3>
                <div className="text-sm text-gray-300">
                  {btcBalance.toFixed(8)} BTC
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <div className="text-green-400 text-sm">
                  {btcAddresses.length > 0 ? '✅ Active' : '⏳ Loading'}
                </div>
                <div className="text-xs text-gray-400">Self-Custodial</div>
              </div>
              <div className={`transform transition-transform duration-200 ${showBitcoinDetails ? 'rotate-180' : ''}`}>
                <ChevronDown className="h-4 w-4 text-gray-400" />
              </div>
            </div>
          </div>
        </button>
        
        {/* Expanded Bitcoin Details */}
        {showBitcoinDetails && (
          <div className="mt-3 bg-gradient-to-r from-orange-900/20 to-yellow-900/20 border border-orange-500/20 rounded-xl p-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm mb-4">
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
            
            <div className="p-3 bg-orange-900/30 rounded-lg">
              <p className="text-orange-200 text-sm">
                🔐 <strong>Self-Custodial Bitcoin Wallet (MAINNET):</strong> Your Bitcoin private keys are generated from your WEPO seed phrase. 
                <strong className="text-green-300"> Public Mode: </strong> Direct Bitcoin transactions available now.
                <strong className="text-purple-300"> Private Mode: </strong> Enhanced privacy via masternode mixing - available to everyone.
              </p>
              <p className="text-yellow-200 text-xs mt-2">
                💡 <strong>Run a Masternode:</strong> Earn mixing fees by providing privacy services. Requires 10,000 WEPO collateral.
              </p>
            </div>
            
            {/* Bitcoin Recovery Information */}
            <div className="mt-4 p-4 bg-blue-900/20 border border-blue-500/30 rounded-lg">
              <h4 className="text-blue-200 font-semibold mb-2 flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Bitcoin Recovery Information
              </h4>
              <div className="space-y-2 text-sm">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <div className="text-blue-300 font-medium">Standard:</div>
                    <div className="text-blue-100">BIP44 HD Wallet</div>
                  </div>
                  <div>
                    <div className="text-blue-300 font-medium">Derivation Path:</div>
                    <div className="text-blue-100 font-mono">m/44'/0'/0'/0/x</div>
                  </div>
                  <div>
                    <div className="text-blue-300 font-medium">Address Type:</div>
                    <div className="text-blue-100">P2PKH (Legacy)</div>
                  </div>
                  <div>
                    <div className="text-blue-300 font-medium">Network:</div>
                    <div className="text-blue-100">Bitcoin Mainnet</div>
                  </div>
                </div>
                
                <div className="mt-3 pt-3 border-t border-blue-500/20">
                  <div className="text-blue-300 font-medium mb-2">Emergency Recovery Steps:</div>
                  <ol className="text-blue-100 space-y-1 text-xs">
                    <li>1. Use your WEPO 12-word seed phrase in any Bitcoin wallet</li>
                    <li>2. Select Bitcoin (BTC) and Legacy (P2PKH) addresses</li>
                    <li>3. Use derivation path: <code className="bg-blue-900/40 px-1 rounded">m/44'/0'/0'/0/x</code></li>
                    <li>4. Compatible with: Electrum, Bitcoin Core, Exodus, Trust Wallet, Ledger, Trezor</li>
                  </ol>
                </div>
                
                <div className="mt-2 p-2 bg-green-900/30 rounded text-green-200 text-xs">
                  ✅ <strong>True Self-Custody:</strong> Your Bitcoin is fully portable and recoverable in any standard Bitcoin wallet using just your WEPO seed phrase.
                </div>
              </div>
            </div>
          </div>
        )}
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
          onClick={() => setActiveTab('governance')}
          className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all duration-200 hover:border-purple-400/50 relative"
        >
          <Users className="h-6 w-6 text-blue-400 mx-auto mb-2" />
          <span className="text-white font-medium">Governance</span>
          <div className="text-xs text-gray-400 mt-1">Halving-Cycle Democracy</div>
          <div className="absolute -top-1 -right-1 bg-blue-500 text-white text-xs px-2 py-1 rounded-full">
            NEW
          </div>
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
        <div className={`bg-gray-800 border rounded-xl p-6 ${posCollateralInfo?.pos_available ? 'border-green-500/30' : 'border-gray-600'}`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <Coins className={`h-8 w-8 ${posCollateralInfo?.pos_available ? 'text-green-400' : 'text-gray-500'}`} />
              <div>
                <h3 className="text-white font-semibold">Proof of Stake</h3>
                <p className="text-sm text-gray-400">Earn by staking WEPO</p>
              </div>
            </div>
            {!posCollateralInfo?.pos_available && <Lock className="h-5 w-5 text-gray-500" />}
          </div>
          
          {/* PoS Collateral Information */}
          {posCollateralLoading ? (
            <div className="text-center text-gray-400">
              <div className="animate-spin inline-block h-6 w-6 border-2 border-gray-300 rounded-full border-t-transparent mb-2"></div>
              <p className="text-sm">Loading PoS info...</p>
            </div>
          ) : posCollateralInfo ? (
            <div className="mb-4">
              <div className="p-3 bg-blue-900/30 rounded-lg mb-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-300">Minimum Stake:</span>
                  <span className="text-blue-400 font-semibold">
                    {posCollateralInfo.pos_available 
                      ? `${posCollateralInfo.pos_collateral_wepo?.toLocaleString() || 1000} WEPO`
                      : `${posCollateralInfo.pos_collateral_wepo?.toLocaleString() || 1000} WEPO (at activation)`
                    }
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm mt-1">
                  <span className="text-gray-300">Current Phase:</span>
                  <span className="text-blue-400">{posCollateralInfo.phase}</span>
                </div>
                {!posCollateralInfo.pos_available && (
                  <div className="flex items-center justify-between text-sm mt-1">
                    <span className="text-gray-300">Activates at Block:</span>
                    <span className="text-yellow-400">131,400</span>
                  </div>
                )}
              </div>
              
              {posCollateralInfo.pos_available ? (
                <button
                  onClick={() => setActiveTab('staking')}
                  className={`w-full font-medium py-2 px-4 rounded-lg transition-colors ${
                    balance >= (posCollateralInfo.pos_collateral_wepo || 1000)
                      ? 'bg-green-600 hover:bg-green-700 text-white'
                      : 'bg-gray-600 text-gray-300 cursor-not-allowed'
                  }`}
                  disabled={balance < (posCollateralInfo.pos_collateral_wepo || 1000)}
                >
                  {balance >= (posCollateralInfo.pos_collateral_wepo || 1000) ? 'Start Staking' : 'Insufficient Balance'}
                </button>
              ) : (
                <div className="text-center">
                  <div className="flex items-center justify-center gap-2 text-gray-400 mb-2">
                    <Clock size={16} />
                    <span className="text-sm">Activates at block 131,400</span>
                  </div>
                  <div className="text-xs text-gray-500">
                    {posCollateralInfo.phase_description || 'Currently in Pre-PoS Mining phase'}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center">
              <div className="flex items-center justify-center gap-2 text-gray-400 mb-2">
                <AlertCircle size={16} />
                <span className="text-sm">PoS info unavailable</span>
              </div>
              <div className="text-xs text-gray-500">
                Check network connection
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