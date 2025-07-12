import React, { useState, useEffect } from 'react';
import { 
  Pickaxe, 
  Users, 
  Clock, 
  Zap, 
  ArrowLeft, 
  Calendar,
  Globe,
  Award,
  TrendingUp,
  Timer,
  Play,
  Square,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';
import { useQuantum } from '../contexts/QuantumContext';

const CommunityMining = ({ onBack, miningMode = 'genesis' }) => {
  const { wallet } = useWallet();
  const { quantumWallet, isQuantumMode } = useQuantum();
  
  const [isConnected, setIsConnected] = useState(false);
  const [isMining, setIsMining] = useState(false);
  const [miningStats, setMiningStats] = useState({
    hashRate: 0,
    difficulty: '0x1d00ffff',
    connectedMiners: 0,
    timeToLaunch: null,
    blockReward: 400,
    estimatedTime: null,
    currentPhase: 'Phase 1'
  });
  const [miningLogs, setMiningLogs] = useState([]);
  const [genesisStatus, setGenesisStatus] = useState('waiting'); // waiting, active, found

  // Christmas Day 2025 3pm EST = 8pm UTC
  const LAUNCH_TIMESTAMP = new Date('2025-12-25T20:00:00Z').getTime();

  const currentWallet = isQuantumMode ? quantumWallet : wallet;

  useEffect(() => {
    // Load mining status and stats
    loadMiningStatus();
    
    // Set up polling for real-time updates
    const interval = setInterval(() => {
      if (isConnected || isMining) {
        updateMiningStats();
      }
      updateCountdown();
    }, 1000);

    return () => clearInterval(interval);
  }, [isConnected, isMining]);

  const loadMiningStatus = async () => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/status`);
      
      if (response.ok) {
        const data = await response.json();
        setMiningStats(prev => ({
          ...prev,
          connectedMiners: data.connected_miners || 0,
          difficulty: data.difficulty || '0x1d00ffff',
          blockReward: data.block_reward || 400,
          currentPhase: data.mining_phase || 'Phase 1'
        }));
        setGenesisStatus(data.genesis_status || 'waiting');
      }
    } catch (error) {
      console.error('Failed to load mining status:', error);
    }
  };

  const updateMiningStats = async () => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/stats/${currentWallet?.address}`);
      
      if (response.ok) {
        const data = await response.json();
        setMiningStats(prev => ({
          ...prev,
          hashRate: data.hash_rate || 0,
          connectedMiners: data.connected_miners || 0,
          estimatedTime: data.estimated_time || null
        }));
      }
    } catch (error) {
      console.error('Failed to update mining stats:', error);
    }
  };

  const updateCountdown = () => {
    const now = Date.now();
    const timeRemaining = LAUNCH_TIMESTAMP - now;
    
    if (timeRemaining > 0) {
      setMiningStats(prev => ({
        ...prev,
        timeToLaunch: timeRemaining
      }));
    } else if (miningMode === 'genesis' && genesisStatus === 'waiting') {
      setGenesisStatus('active');
    }
  };

  const connectToMining = async () => {
    try {
      setIsConnected(true);
      addMiningLog('🌐 Connecting to WEPO mining network...');
      
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: currentWallet?.address,
          mining_mode: miningMode,
          wallet_type: isQuantumMode ? 'quantum' : 'regular'
        })
      });
      
      if (response.ok) {
        addMiningLog('✅ Connected to mining network successfully!');
        addMiningLog(`⛏️ Ready to mine with ${isQuantumMode ? 'quantum-resistant' : 'standard'} wallet`);
      } else {
        throw new Error('Failed to connect to mining network');
      }
    } catch (error) {
      addMiningLog(`❌ Connection failed: ${error.message}`);
      setIsConnected(false);
    }
  };

  const startMining = async () => {
    if (!isConnected) {
      await connectToMining();
    }

    try {
      setIsMining(true);
      addMiningLog('🚀 Starting mining operation...');
      
      if (miningMode === 'genesis') {
        addMiningLog('🎄 Joining Christmas Genesis Mining Event!');
        addMiningLog('⛏️ Mining for Block #0 - The Beginning of WEPO');
      } else {
        addMiningLog(`⚡ Starting ${miningStats.currentPhase} mining (${miningStats.blockReward} WEPO reward)`);
      }
      
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: currentWallet?.address,
          mining_mode: miningMode
        })
      });
      
      if (response.ok) {
        addMiningLog('✅ Mining started successfully!');
        addMiningLog('📊 Hash rate will update in real-time...');
      }
    } catch (error) {
      addMiningLog(`❌ Mining start failed: ${error.message}`);
      setIsMining(false);
    }
  };

  const stopMining = async () => {
    try {
      setIsMining(false);
      addMiningLog('⏹️ Stopping mining operation...');
      
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      await fetch(`${backendUrl}/api/mining/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: currentWallet?.address
        })
      });
      
      addMiningLog('✅ Mining stopped successfully');
      setMiningStats(prev => ({ ...prev, hashRate: 0 }));
    } catch (error) {
      addMiningLog(`❌ Stop mining failed: ${error.message}`);
    }
  };

  const addMiningLog = (message) => {
    const timestamp = new Date().toLocaleTimeString();
    setMiningLogs(prev => [
      { time: timestamp, message },
      ...prev.slice(0, 49) // Keep last 50 logs
    ]);
  };

  const formatTimeRemaining = (ms) => {
    if (!ms || ms <= 0) return 'Launch time reached!';
    
    const days = Math.floor(ms / (1000 * 60 * 60 * 24));
    const hours = Math.floor((ms % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((ms % (1000 * 60)) / 1000);
    
    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
    return `${minutes}m ${seconds}s`;
  };

  const formatHashRate = (rate) => {
    if (rate >= 1000000) return `${(rate / 1000000).toFixed(2)} MH/s`;
    if (rate >= 1000) return `${(rate / 1000).toFixed(2)} KH/s`;
    return `${rate.toFixed(2)} H/s`;
  };

  const renderGenesisCountdown = () => (
    <div className="bg-gradient-to-r from-red-900/30 to-green-900/30 border border-red-500/30 rounded-xl p-6 mb-6">
      <div className="text-center">
        <div className="flex items-center justify-center gap-2 mb-4">
          <Calendar className="h-8 w-8 text-red-400" />
          <h2 className="text-2xl font-bold text-white">🎄 Christmas Genesis Launch</h2>
        </div>
        
        <div className="text-4xl font-bold text-green-400 mb-2">
          {formatTimeRemaining(miningStats.timeToLaunch)}
        </div>
        
        <p className="text-gray-300 mb-4">
          December 25, 2025 • 3:00 PM EST (8:00 PM UTC)
        </p>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">Block Reward</div>
            <div className="text-white font-semibold">{miningStats.blockReward} WEPO</div>
          </div>
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">Connected Miners</div>
            <div className="text-white font-semibold">{miningStats.connectedMiners}</div>
          </div>
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">Difficulty</div>
            <div className="text-white font-semibold">Fair Start</div>
          </div>
          <div className="bg-black/30 rounded-lg p-3">
            <div className="text-gray-400">Network</div>
            <div className="text-green-400 font-semibold">Global P2P</div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderMiningInterface = () => (
    <div className="space-y-6">
      {/* Mining Status */}
      <div className="bg-gray-800/50 border border-purple-500/30 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Pickaxe className={`h-8 w-8 ${isMining ? 'text-green-400' : 'text-gray-400'}`} />
            <div>
              <h3 className="text-white font-semibold">
                {miningMode === 'genesis' ? 'Genesis Block Mining' : 'WEPO Mining'}
              </h3>
              <p className="text-sm text-gray-400">
                {miningMode === 'genesis' 
                  ? 'Community mining for Block #0' 
                  : `${miningStats.currentPhase} - ${miningStats.blockReward} WEPO per block`
                }
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {!isConnected ? (
              <button
                onClick={connectToMining}
                className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
              >
                <Globe className="h-4 w-4 mr-2 inline" />
                Connect
              </button>
            ) : !isMining ? (
              <button
                onClick={startMining}
                className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition-colors"
                disabled={miningMode === 'genesis' && genesisStatus !== 'active'}
              >
                <Play className="h-4 w-4 mr-2 inline" />
                Start Mining
              </button>
            ) : (
              <button
                onClick={stopMining}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors"
              >
                <Square className="h-4 w-4 mr-2 inline" />
                Stop Mining
              </button>
            )}
          </div>
        </div>
        
        {/* Mining Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-700/50 rounded-lg p-3">
            <div className="text-gray-400 text-sm">Hash Rate</div>
            <div className="text-white font-semibold">
              {formatHashRate(miningStats.hashRate)}
            </div>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-3">
            <div className="text-gray-400 text-sm">Network Miners</div>
            <div className="text-white font-semibold">{miningStats.connectedMiners}</div>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-3">
            <div className="text-gray-400 text-sm">Status</div>
            <div className={`font-semibold ${isMining ? 'text-green-400' : 'text-gray-400'}`}>
              {isMining ? 'Mining' : isConnected ? 'Connected' : 'Disconnected'}
            </div>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-3">
            <div className="text-gray-400 text-sm">Algorithm</div>
            <div className="text-white font-semibold">
              {miningMode === 'genesis' ? 'CPU Fair' : 'Dual Layer'}
            </div>
          </div>
        </div>
      </div>

      {/* Post-Genesis Mining Info */}
      {miningMode !== 'genesis' && (
        <div className="bg-blue-900/20 border border-blue-500/30 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <Zap className="h-6 w-6 text-blue-400" />
            <h3 className="text-white font-semibold">Dual-Layer Mining System</h3>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div className="bg-black/30 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 bg-green-400 rounded-full"></div>
                <span className="text-white font-medium">CPU/GPU Layer (60%)</span>
              </div>
              <p className="text-gray-300 mb-2">Argon2 algorithm - Wallet miners welcome</p>
              <p className="text-green-400 text-xs">Your current mode: Casual mining</p>
            </div>
            
            <div className="bg-black/30 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-3 h-3 bg-orange-400 rounded-full"></div>
                <span className="text-white font-medium">ASIC Layer (40%)</span>
              </div>
              <p className="text-gray-300 mb-2">SHA-256 algorithm - Traditional miners</p>
              <p className="text-orange-400 text-xs">Higher efficiency for dedicated hardware</p>
            </div>
          </div>
          
          <div className="mt-4 p-3 bg-purple-900/30 rounded-lg">
            <p className="text-purple-200 text-sm">
              💡 <strong>Fair Mining:</strong> Both layers are profitable. ASICs get 4-6x advantage, 
              but wallet miners remain competitive with steady rewards.
            </p>
          </div>
        </div>
      )}

      {/* Mining Logs */}
      <div className="bg-gray-800/50 border border-gray-600 rounded-xl">
        <div className="p-4 border-b border-gray-600">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-purple-400" />
            Mining Activity Log
          </h3>
        </div>
        
        <div className="p-4 h-64 overflow-y-auto">
          {miningLogs.length === 0 ? (
            <div className="text-center py-8">
              <Timer className="h-12 w-12 text-gray-500 mx-auto mb-4" />
              <p className="text-gray-400">No mining activity yet</p>
              <p className="text-sm text-gray-500 mt-1">
                Connect and start mining to see activity
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {miningLogs.map((log, index) => (
                <div key={index} className="flex items-start gap-3 text-sm">
                  <span className="text-gray-500 shrink-0">{log.time}</span>
                  <span className="text-gray-300">{log.message}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <button
          onClick={onBack}
          className="text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="h-6 w-6" />
        </button>
        <div className="flex items-center gap-3">
          <Pickaxe className="h-8 w-8 text-purple-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">
              {miningMode === 'genesis' ? '🎄 Genesis Mining' : '⚡ WEPO Mining'}
            </h1>
            <p className="text-gray-400">
              {miningMode === 'genesis' 
                ? 'Join the Christmas community mining event'
                : 'Mine WEPO blocks and earn rewards'
              }
            </p>
          </div>
        </div>
      </div>

      {/* Wallet Info */}
      <div className="bg-gray-800/30 border border-purple-500/20 rounded-xl p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-full ${
              isQuantumMode ? 'bg-purple-600/20' : 'bg-blue-600/20'
            }`}>
              {isQuantumMode ? <Zap className="h-5 w-5 text-purple-400" /> : <Users className="h-5 w-5 text-blue-400" />}
            </div>
            <div>
              <p className="text-white font-medium">
                Mining with {isQuantumMode ? 'Quantum' : 'Regular'} Wallet
              </p>
              <p className="text-sm text-gray-400">
                {currentWallet?.address?.substring(0, 20)}...
              </p>
            </div>
          </div>
          {isQuantumMode && (
            <div className="text-right">
              <div className="text-purple-400 text-sm font-medium">Post-Quantum Secure</div>
              <div className="text-gray-400 text-xs">Dilithium signatures</div>
            </div>
          )}
        </div>
      </div>

      {/* Genesis Launch Countdown or Mining Interface */}
      {miningMode === 'genesis' && genesisStatus === 'waiting' && miningStats.timeToLaunch > 0 ? (
        renderGenesisCountdown()
      ) : (
        renderMiningInterface()
      )}

      {/* Genesis Found Message */}
      {miningMode === 'genesis' && genesisStatus === 'found' && (
        <div className="bg-green-900/30 border border-green-500/30 rounded-xl p-6 text-center">
          <CheckCircle className="h-16 w-16 text-green-400 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">🎉 Genesis Block Found!</h2>
          <p className="text-green-400 mb-4">
            WEPO blockchain is now live! The community has successfully mined Block #0.
          </p>
          <p className="text-gray-300 text-sm">
            Mining will now transition to the dual-layer system for ongoing block production.
          </p>
        </div>
      )}

      {/* Warning for Genesis Mode */}
      {miningMode === 'genesis' && genesisStatus === 'waiting' && (
        <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-400" />
            <div>
              <p className="text-yellow-400 font-medium">Genesis Mining Event</p>
              <p className="text-gray-300 text-sm">
                This is a one-time community event. Once the genesis block is found, 
                mining will transition to the regular dual-layer system.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CommunityMining;