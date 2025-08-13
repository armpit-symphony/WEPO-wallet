import React, { useEffect, useState } from 'react';
import { Eye, EyeOff, Send, Download, Settings as SettingsIcon, Pickaxe, Shield, LogOut, Bitcoin, ChevronDown, Coins } from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';
import SendWepo from './SendWepo';
import ReceiveWepo from './ReceiveWepo';
import QuantumVault from './QuantumVault';
import CommunityMining from './CommunityMining';
import SettingsPanel from './SettingsPanel';
import QuantumMessaging from './QuantumMessaging';

const Dashboard = ({ onLogout }) => {
  const {
    wallet,
    balance,
    transactions,
    loadWalletData,
    setWallet,
    setBalance,
    setTransactions,
    logout
  } = useWallet();

  const [activeTab, setActiveTab] = useState('overview');
  const [showBalance, setShowBalance] = useState(true);
  const [isPreGenesis, setIsPreGenesis] = useState(true);
  const [showVaultModal, setShowVaultModal] = useState(false);
  const [genesisLaunchTime, setGenesisLaunchTime] = useState(null);
  const [posCountdown, setPosCountdown] = useState('Calculating...');

  useEffect(() => {
    // Restore session wallet and data
    const init = async () => {
      try {
        if (!wallet) {
          const sw = sessionStorage.getItem('wepo_current_wallet');
          if (sw) {
            const w = JSON.parse(sw);
            setWallet(w);
            await loadWalletData(w.address);
          }
        }
      } catch (e) {
        setBalance(0);
        setTransactions([]);
      }
    };
    init();
  }, [wallet, setWallet, setBalance, setTransactions, loadWalletData]);

  useEffect(() => {
    // Determine pre-genesis from backend status
    const check = async () => {
      try {
        const backendUrl = process.env.REACT_APP_BACKEND_URL || '';
        const r = await fetch(`${backendUrl}/api/mining/status`);
        if (r.ok) {
          const d = await r.json();
          const pow = d.genesis_status === 'found' || d.mining_mode === 'pow';
          setIsPreGenesis(!pow);
          if (d.genesis_launch_time) setGenesisLaunchTime(d.genesis_launch_time);
        } else {
          setIsPreGenesis(true);
        }
      } catch {
        setIsPreGenesis(true);
      }
    };
    check();
  }, []);

  const formatBalance = (amt) => new Intl.NumberFormat('en-US', { minimumFractionDigits: 4, maximumFractionDigits: 4 }).format(amt || 0);
  const short = (s) => (s && s.length > 10 ? `${s.substring(0, 10)}...${s.substring(s.length - 6)}` : s || 'N/A');

  const [showBitcoinDetails, setShowBitcoinDetails] = useState(false);

  const Overview = () => (
    <div className="space-y-6">
      <div className="rounded-2xl p-6 text-white bg-gradient-to-r from-purple-600 to-blue-600">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="text-purple-100 text-sm font-medium mb-2">Total Balance</div>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-3xl font-bold">{showBalance ? formatBalance(balance) : '••••••••'}</span>
              <span className="text-xl text-purple-200">WEPO</span>
              <button onClick={() => setShowBalance(!showBalance)} className="text-purple-200 hover:text-white transition-colors">
                {showBalance ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>
          </div>
          <div className="text-right">
            <Shield className="h-12 w-12 text-purple-200 mb-2" />
          </div>
        </div>
        <div className="text-sm text-purple-100">Address: {short(wallet?.address)}</div>
        {!isPreGenesis && (
          <div className="text-xs text-green-200 mt-2">Network: PoW active</div>
        )}
        {isPreGenesis && (
          <div className="text-xs text-yellow-200 mt-2">Network: Pre-Genesis • Countdown to Genesis: {genesisLaunchTime ? Math.max(0, Math.floor((genesisLaunchTime*1000 - Date.now())/1000)) + 's' : 'TBA'}</div>
        )}
      </div>

      {/* BTC Wallet Section (compact) */}
      <div className="mb-6">
        <button onClick={() => setShowBitcoinDetails(!showBitcoinDetails)} className="w-full bg-gradient-to-r from-orange-900/30 to-yellow-900/30 border border-orange-500/30 rounded-xl p-4 hover:from-orange-900/40 hover:to-yellow-900/40 transition-all duration-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Bitcoin className="h-6 w-6 text-orange-400" />
              <div className="text-left">
                <h3 className="text-white font-semibold">BTC</h3>
                <div className="text-sm text-gray-300">0.00000000 BTC</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="text-right">
                <div className="text-green-400 text-sm">{true ? '✅ Active' : '⏳ Initializing...'}</div>
                <div className="text-xs text-gray-400">Self-Custodial</div>
              </div>
              <div className={`transform transition-transform duration-200 ${showBitcoinDetails ? 'rotate-180' : ''}`}>
                <ChevronDown className="h-4 w-4 text-gray-400" />
              </div>
            </div>
          </div>
        </button>
        {showBitcoinDetails && (
          <div className="mt-3 bg-gradient-to-r from-orange-900/20 to-yellow-900/20 border border-orange-500/20 rounded-xl p-6">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm mb-4">
              <div className="bg-black/30 rounded-lg p-3">
                <div className="text-gray-400">BTC Balance</div>
                <div className="text-orange-400 font-semibold">0.00000000 BTC</div>
                <div className="text-green-400 text-xs mt-1">Mainnet</div>
              </div>
              <div className="bg-black/30 rounded-lg p-3">
                <div className="text-gray-400">Mode</div>
                <div className="text-white font-semibold">Public Mode</div>
                <div className="text-blue-400 text-xs mt-1">Direct Bitcoin</div>
              </div>
              <div className="bg-black/30 rounded-lg p-3">
                <div className="text-gray-400">Address Type</div>
                <div className="text-white font-semibold">P2PKH (Legacy)</div>
              </div>
              <div className="bg-black/30 rounded-lg p-3">
                <div className="text-gray-400">Derivation</div>
                <div className="text-white font-mono">m/44'/0'/0'/0/x</div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <button onClick={() => setActiveTab('send')} className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all">
          <Send className="h-6 w-6 text-purple-400 mx-auto mb-2" />
          <span className="text-white font-medium">Send WEPO</span>
        </button>
        <button onClick={() => setActiveTab('receive')} className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all">
          <Download className="h-6 w-6 text-blue-400 mx-auto mb-2" />
          <span className="text-white font-medium">Receive WEPO</span>
        </button>
        <button onClick={() => setShowVaultModal(true)} className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all">
          <Shield className="h-6 w-6 text-purple-400 mx-auto mb-2" />
          <span className="text-white font-medium">Quantum Vault</span>
        </button>
        <button onClick={() => setActiveTab('mining')} className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all">
          <Pickaxe className="h-6 w-6 text-yellow-400 mx-auto mb-2" />
          <span className="text-white font-medium">Community Mining</span>
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <button onClick={() => setActiveTab('messaging')} className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all">
          <span className="text-white font-medium">Quantum Messages</span>
        </button>
        <button onClick={() => setActiveTab('settings')} className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all">
          <SettingsIcon className="h-6 w-6 text-gray-400 mx-auto mb-2" />
          <span className="text-white font-medium">Settings</span>
        </button>
        <button onClick={() => { logout(); onLogout && onLogout(); }} className="bg-gray-800/50 hover:bg-gray-700/50 border border-purple-500/30 rounded-xl p-4 text-center transition-all">
          <LogOut className="h-6 w-6 text-red-400 mx-auto mb-2" />
          <span className="text-white font-medium">Logout</span>
        </button>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {activeTab === 'overview' && <Overview />}
      {activeTab === 'send' && <SendWepo onClose={() => setActiveTab('overview')} isPreGenesis={isPreGenesis} />}
      {activeTab === 'receive' && <ReceiveWepo onClose={() => setActiveTab('overview')} />}
      {activeTab === 'mining' && <CommunityMining onBack={() => setActiveTab('overview')} isPreGenesis={isPreGenesis} />}
      {activeTab === 'settings' && <SettingsPanel onClose={() => setActiveTab('overview')} />}
      {activeTab === 'messaging' && <QuantumMessaging onBack={() => setActiveTab('overview')} />}

      {showVaultModal && (
        <QuantumVault onClose={() => setShowVaultModal(false)} isPreGenesis={isPreGenesis} />
      )}
    </div>
  );
};

export default Dashboard;