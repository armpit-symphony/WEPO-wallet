import React, { useState, useEffect, useRef } from 'react';
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
  CheckCircle,
  Settings,
  Cpu,
  Activity
} from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';

const CommunityMining = ({ onBack, miningMode = 'genesis' }) => {
  const { wallet } = useWallet();
  
  // Mining states
  const [isConnected, setIsConnected] = useState(false);
  const [isMining, setIsMining] = useState(false);
  const [miningStats, setMiningStats] = useState({
    hashRate: 0,
    difficulty: '0x1d00ffff',
    connectedMiners: 0,
    activeMiners: 0,
    timeToLaunch: null,
    blockReward: 0,
    estimatedTime: null,
    currentPhase: 'Genesis Block',
    totalHashrate: 0,
    blocksFound: 0,
    networkRank: 0
  });
  const [miningLogs, setMiningLogs] = useState([]);
  const [cpuUsage, setCpuUsage] = useState(25);
  const [personalStats, setPersonalStats] = useState({
    sharesSubmitted: 0,
    blocksFound: 0,
    uptime: 0,
    totalHashes: 0
  });
  const [showSettings, setShowSettings] = useState(false);
  
  // WebWorker refs
  const miningWorker = useRef(null);
  const statsInterval = useRef(null);
  
  // Dynamic mode detection
  const [currentMode, setCurrentMode] = useState('genesis');
  const [modeDisplay, setModeDisplay] = useState('🎄 Genesis Block Mining');
  
  // Christmas Day 2025 3pm EST = 8pm UTC
  const LAUNCH_TIMESTAMP = new Date('2025-12-25T20:00:00Z').getTime();

  useEffect(() => {
    // Initialize mining worker
    initializeMiningWorker();
    
    // Load initial mining status
    loadMiningStatus();
    
    // Set up polling for real-time updates
    const interval = setInterval(() => {
      if (isConnected || isMining) {
        updateMiningStats();
        updatePersonalStats();
      }
      updateCountdown();
    }, 2000); // Poll every 2 seconds

    return () => {
      clearInterval(interval);
      if (statsInterval.current) {
        clearInterval(statsInterval.current);
      }
      if (miningWorker.current) {
        miningWorker.current.terminate();
      }
    };
  }, []);

  const initializeMiningWorker = () => {
    try {
      miningWorker.current = new Worker('/mining-worker.js');
      
      miningWorker.current.onmessage = (e) => {
        const { type, data } = e.data;
        
        switch (type) {
          case 'WORKER_READY':
            addMiningLog('⚙️ Mining engine initialized');
            break;
          case 'MINING_STARTED':
            addMiningLog('🚀 Mining started successfully');
            break;
          case 'MINING_STOPPED':
            addMiningLog(`⏹️ Mining stopped. Total hashes: ${data.totalHashes.toLocaleString()}`);
            break;
          case 'HASHRATE_UPDATE':
            setMiningStats(prev => ({ ...prev, hashRate: data.hashrate }));
            updateHashrateOnServer(data.hashrate);
            break;
          case 'SOLUTION_FOUND':
            handleSolutionFound(data);
            break;
          case 'JOB_UPDATED':
            addMiningLog(`📋 New mining job: ${data.jobId}`);
            break;
        }
      };
      
      miningWorker.current.onerror = (error) => {
        console.error('Mining worker error:', error);
        addMiningLog(`❌ Mining worker error: ${error.message}`);
      };
    } catch (error) {
      console.error('Failed to initialize mining worker:', error);
      addMiningLog('❌ Failed to initialize mining engine');
    }
  };

  const loadMiningStatus = async () => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/status`);
      
      if (response.ok) {
        const data = await response.json();
        
        // Update mode based on server response
        setCurrentMode(data.mining_mode || 'genesis');
        setModeDisplay(data.mode_display || '🎄 Genesis Block Mining');
        
        setMiningStats(prev => ({
          ...prev,
          connectedMiners: data.connected_miners || 0,
          activeMiners: data.active_miners || 0,
          totalHashrate: data.total_hashrate || 0,
          difficulty: data.network_difficulty || 1.0,
          blocksFound: data.blocks_found || 0,
          timeToLaunch: data.time_to_launch || null,
          currentPhase: data.mode_display || 'Genesis Block'
        }));
      }
    } catch (error) {
      console.error('Failed to load mining status:', error);
      addMiningLog('⚠️ Could not load network status');
    }
  };

  const updateMiningStats = async () => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/status`);
      
      if (response.ok) {
        const data = await response.json();
        
        // Check if mode changed (genesis → pow)
        if (data.mining_mode !== currentMode) {
          setCurrentMode(data.mining_mode);
          setModeDisplay(data.mode_display);
          addMiningLog(`🔄 Mining mode changed to: ${data.mode_display}`);
        }
        
        setMiningStats(prev => ({
          ...prev,
          connectedMiners: data.connected_miners || prev.connectedMiners,
          activeMiners: data.active_miners || prev.activeMiners,
          totalHashrate: data.total_hashrate || prev.totalHashrate,
          blocksFound: data.blocks_found || prev.blocksFound,
          timeToLaunch: data.time_to_launch || null
        }));
      }
    } catch (error) {
      console.error('Failed to update mining stats:', error);
    }
  };

  const updatePersonalStats = async () => {
    if (!wallet?.address) return;
    
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/stats/${wallet.address}`);
      
      if (response.ok) {
        const data = await response.json();
        if (!data.error) {
          setPersonalStats({
            sharesSubmitted: data.shares_submitted || 0,
            blocksFound: data.blocks_found || 0,
            uptime: data.uptime || 0,
            totalHashes: personalStats.totalHashes
          });
          setMiningStats(prev => ({
            ...prev,
            networkRank: data.network_rank || 0
          }));
        }
      }
    } catch (error) {
      console.error('Failed to update personal stats:', error);
    }
  };

  const updateCountdown = () => {
    const now = Date.now();
    const timeRemaining = LAUNCH_TIMESTAMP - now;
    
    if (timeRemaining > 0 && currentMode === 'genesis') {
      setMiningStats(prev => ({
        ...prev,
        timeToLaunch: timeRemaining
      }));
    }
  };

  const connectToMining = async () => {
    if (!wallet?.address) {
      addMiningLog('❌ Wallet not connected');
      return;
    }

    try {
      setIsConnected(true);
      addMiningLog('🌐 Connecting to WEPO mining network...');
      
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/connect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: wallet.address,
          mining_mode: currentMode,
          wallet_type: 'regular'
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        addMiningLog('✅ Connected to mining network successfully!');
        addMiningLog(`⛏️ Network miners: ${data.network_miners}`);
        addMiningLog(`🎯 Mode: ${data.mining_mode}`);
        
        // Update stats immediately
        updateMiningStats();
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

    if (!wallet?.address) {
      addMiningLog('❌ Wallet address required');
      return;
    }

    try {
      setIsMining(true);
      addMiningLog('🚀 Starting mining operation...');
      
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: wallet.address
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        addMiningLog(`✅ ${data.message}`);
        addMiningLog(`⚙️ CPU Usage: ${cpuUsage}%`);
        addMiningLog(`🎯 ${data.status}`);
        
        // Start WebWorker mining
        if (miningWorker.current && data.mining_job) {
          miningWorker.current.postMessage({
            type: 'START_MINING',
            data: data.mining_job
          });
          
          // Set CPU usage
          miningWorker.current.postMessage({
            type: 'SET_CPU_USAGE',
            data: { cpuUsage: cpuUsage }
          });
        }
        
        // Start periodic job updates
        statsInterval.current = setInterval(async () => {
          if (isMining) {
            await updateMiningJob();
          }
        }, 30000); // Update job every 30 seconds
        
      } else {
        throw new Error('Failed to start mining');
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
      
      // Stop WebWorker
      if (miningWorker.current) {
        miningWorker.current.postMessage({ type: 'STOP_MINING' });
      }
      
      // Stop job updates
      if (statsInterval.current) {
        clearInterval(statsInterval.current);
        statsInterval.current = null;
      }
      
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      await fetch(`${backendUrl}/api/mining/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: wallet.address
        })
      });
      
      addMiningLog('✅ Mining stopped successfully');
      setMiningStats(prev => ({ ...prev, hashRate: 0 }));
    } catch (error) {
      addMiningLog(`❌ Stop mining failed: ${error.message}`);
    }
  };

  const updateMiningJob = async () => {
    if (!wallet?.address) return;
    
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/work/${wallet.address}`);
      
      if (response.ok) {
        const jobData = await response.json();
        
        // Send new job to WebWorker
        if (miningWorker.current) {
          miningWorker.current.postMessage({
            type: 'UPDATE_JOB',
            data: jobData
          });
        }
      }
    } catch (error) {
      console.error('Failed to update mining job:', error);
    }
  };

  const handleSolutionFound = async (solutionData) => {
    addMiningLog(`🎉 Solution found! Hash: ${solutionData.hash.substring(0, 16)}...`);
    
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/mining/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: wallet.address,
          job_id: solutionData.jobId,
          nonce: solutionData.nonce,
          hash: solutionData.hash
        })
      });
      
      if (response.ok) {
        const result = await response.json();
        
        if (result.accepted) {
          if (result.type === 'block') {
            addMiningLog(`🎉 BLOCK FOUND! ${result.message}`);
            addMiningLog(`💰 Reward: ${result.reward} WEPO`);
            
            if (result.height === 0) {
              // Genesis block found - mode will change
              addMiningLog('🎄 GENESIS BLOCK MINED! Welcome to WEPO network!');
            }
          } else {
            addMiningLog(`✅ Share accepted (${personalStats.sharesSubmitted + 1})`);
          }
          
          // Update personal stats immediately
          updatePersonalStats();
        } else {
          addMiningLog('❌ Solution rejected');
        }
      }
    } catch (error) {
      addMiningLog(`❌ Submit failed: ${error.message}`);
    }
  };

  const updateHashrateOnServer = async (hashrate) => {
    if (!wallet?.address) return;
    
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      await fetch(`${backendUrl}/api/mining/hashrate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: wallet.address,
          hashrate: hashrate
        })
      });
    } catch (error) {
      // Silently fail - not critical
    }
  };

  const updateCpuUsage = (newUsage) => {
    setCpuUsage(newUsage);
    if (miningWorker.current) {
      miningWorker.current.postMessage({
        type: 'SET_CPU_USAGE',
        data: { cpuUsage: newUsage }
      });
    }
    addMiningLog(`⚙️ CPU usage updated to ${newUsage}%`);
  };

  const addMiningLog = (message) => {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = `[${timestamp}] ${message}`;
    
    setMiningLogs(prev => {
      const newLogs = [logEntry, ...prev];
      return newLogs.slice(0, 50); // Keep last 50 logs
    });
  };

  const formatTime = (seconds) => {
    if (!seconds) return 'N/A';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hours}h ${minutes}m ${secs}s`;
  };

  const formatHashrate = (hashrate) => {
    if (hashrate >= 1000000000) return `${(hashrate / 1000000000).toFixed(1)} GH/s`;
    if (hashrate >= 1000000) return `${(hashrate / 1000000).toFixed(1)} MH/s`;
    if (hashrate >= 1000) return `${(hashrate / 1000).toFixed(1)} KH/s`;
    return `${hashrate.toFixed(0)} H/s`;
  };

  const renderCountdown = () => {
    if (currentMode !== 'genesis' || !miningStats.timeToLaunch) return null;
    
    const days = Math.floor(miningStats.timeToLaunch / (1000 * 60 * 60 * 24));
    const hours = Math.floor((miningStats.timeToLaunch % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((miningStats.timeToLaunch % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((miningStats.timeToLaunch % (1000 * 60)) / 1000);
    
    return (
      <div className="bg-gradient-to-r from-green-900/30 to-red-900/30 rounded-lg p-4 border border-green-600/30">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Calendar className="w-5 h-5 text-green-400" />
            <span className="text-green-400 font-medium">Christmas Genesis Launch</span>
          </div>
          <Timer className="w-5 h-5 text-red-400 animate-pulse" />
        </div>
        <div className="grid grid-cols-4 gap-2 text-center">
          <div className="bg-black/30 rounded p-2">
            <div className="text-2xl font-bold text-white">{days}</div>
            <div className="text-xs text-gray-400">DAYS</div>
          </div>
          <div className="bg-black/30 rounded p-2">
            <div className="text-2xl font-bold text-white">{hours}</div>
            <div className="text-xs text-gray-400">HOURS</div>
          </div>
          <div className="bg-black/30 rounded p-2">
            <div className="text-2xl font-bold text-white">{minutes}</div>
            <div className="text-xs text-gray-400">MINS</div>
          </div>
          <div className="bg-black/30 rounded p-2">
            <div className="text-2xl font-bold text-white">{seconds}</div>
            <div className="text-xs text-gray-400">SECS</div>
          </div>
        </div>
        <div className="text-center mt-2 text-sm text-yellow-400">
          🎄 December 25, 2025 - 3:00 PM EST
        </div>
      </div>
    );
  };
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