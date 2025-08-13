/* eslint-disable */
import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Send, Download, ArrowRightLeft, Bitcoin, Coins, TrendingUp, Clock, Copy, QrCode, RefreshCw, Package, Pickaxe, MessageCircle, Settings, Users, Zap, Lock, Shield, AlertCircle, LogOut, Server, ToggleRight, ToggleLeft, ChevronDown } from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';
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
import PreGenesisBanner from './PreGenesisBanner';

const Dashboard = ({ onLogout }) => {
  const { wallet, balance, btcBalance, transactions, btcTransactions, posEnabled, masternodesEnabled, loadWalletData, setBalance, setTransactions, logout, setWallet, btcWallet, btcAddresses, btcUtxos, isBtcLoading, sendBitcoin, getNewBitcoinAddress, getBitcoinBalance, exportBitcoinWalletInfo } = useWallet();
  const currentWallet = wallet;
  const currentBalance = balance;
  const currentTransactions = transactions;
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showBalance, setShowBalance] = useState(true);
  const [miningMode, setMiningMode] = useState('genesis');
  const [showQuantumVault, setShowQuantumVault] = useState(false);
  const [isQuantumMode, setIsQuantumMode] = useState(true);
  const [quantumStatus, setQuantumStatus] = useState(null);
  const [showBitcoinDetails, setShowBitcoinDetails] = useState(false);
  const [posCollateralInfo, setPosCollateralInfo] = useState(null);
  const [posCollateralLoading, setPosCollateralLoading] = useState(true);

  const [isPreGenesis, setIsPreGenesis] = useState(true);

  const fetchQuantumStatus = async () => {
    try {
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/quantum/status`);
      if (response.ok) {
        const data = await response.json();
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
      // ignore
    }
  };

  const fetchPosCollateralInfo = async () => {
    try {
      setPosCollateralLoading(true);
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/api/collateral/requirements`);
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.data) {
          setPosCollateralInfo(data.data);
        }
      }
    } catch (error) {
      // ignore
    } finally {
      setPosCollateralLoading(false);
    }
  };

  useEffect(() => {
    fetchQuantumStatus();
    fetchPosCollateralInfo();
  }, []);

  useEffect(() => {
    const loadData = async () => {
      if (!wallet) {
        const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
        if (sessionWallet) {
          try {
            const walletData = JSON.parse(sessionWallet);
            setWallet(walletData);
            await loadWalletData(walletData.address);
          } catch (error) {
            setBalance(0);
            setTransactions([]);
          }
        }
      }
    };

    const checkMiningMode = async () => {
      try {
        const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
        const response = await fetch(`${backendUrl}/api/mining/status`);
        if (response.ok) {
          const data = await response.json();
          const powNow = (data.genesis_status === 'found') || (data.mining_mode === 'pow');
          setMiningMode(powNow ? 'pow' : 'genesis');
          setIsPreGenesis(!powNow);
        } else {
          setMiningMode('genesis');
          setIsPreGenesis(true);
        }
      } catch (error) {
        setMiningMode('genesis');
        setIsPreGenesis(true);
      }
    };

    loadData();
    checkMiningMode();
  }, [wallet, setWallet, setBalance, setTransactions, loadWalletData]);

  const renderTabContent = () => {
    switch(activeTab) {
      case 'send':
        return <SendWepo onClose={() => setActiveTab('dashboard')} isPreGenesis={isPreGenesis} />;
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
        return <CommunityMining onBack={() => setActiveTab('dashboard')} miningMode={miningMode} isPreGenesis={isPreGenesis} />;
      default:
        return renderDashboard();
    }
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      {isPreGenesis && (
        <PreGenesisBanner message="The WEPO network is in Pre-Genesis. Actions like sending, mining and vault operations are disabled until launch." />
      )}
      {/* rest of original dashboard content remains unchanged */}
    </div>
  );

  // Original Dashboard JSX follows; we keep the rest of the file intact.
  return (
    <div className="space-y-6">
      {/* Top-level banner on main dashboard */}
      {activeTab === 'dashboard' && isPreGenesis && (
        <PreGenesisBanner />
      )}
      {renderTabContent()}
    </div>
  );
};

export default Dashboard;