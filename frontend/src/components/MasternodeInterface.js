import React, { useState, useEffect } from 'react';
import { Server, ArrowLeft, Shield, TrendingUp, AlertCircle, Clock, Globe, Smartphone, Monitor, Settings, Activity, Zap } from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';

const MasternodeInterface = ({ onClose }) => {
  const { balance, masternodesEnabled } = useWallet();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [masternodeActive, setMasternodeActive] = useState(false);
  const [deviceType, setDeviceType] = useState('computer');
  const [selectedServices, setSelectedServices] = useState([]);
  const [masternodeStats, setMasternodeStats] = useState({
    uptime: 0,
    dailyEarnings: 0,
    servicesActive: 0,
    lastReward: 0,
    totalEarned: 0
  });

  // Device detection
  useEffect(() => {
    const detectDevice = () => {
      const userAgent = navigator.userAgent || navigator.vendor || window.opera;
      const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
      const isTablet = /iPad|Android/i.test(userAgent) && window.innerWidth > 768;
      
      if (isMobile && !isTablet) {
        setDeviceType('mobile');
      } else {
        setDeviceType('computer');
      }
    };
    
    detectDevice();
    window.addEventListener('resize', detectDevice);
    return () => window.removeEventListener('resize', detectDevice);
  }, []);

  // Auto-select services based on device type
  useEffect(() => {
    if (deviceType === 'computer') {
      // Auto-select 3 most suitable services for computers
      setSelectedServices(['network_relay', 'mixing_service', 'dex_relay']);
    } else {
      // Auto-select 2 least resource-intensive services for mobile
      setSelectedServices(['network_relay', 'governance']);
    }
  }, [deviceType]);

  // Mock masternode data with new specifications
  const collateralRequired = 10000;
  const deviceRequirements = {
    computer: {
      uptime: 9,
      services: 3,
      gracePeriod: 48,
      maxEarnings: 4.2
    },
    mobile: {
      uptime: 6,
      services: 2,
      gracePeriod: 24,
      maxEarnings: 2.8
    }
  };

  const availableServices = [
    {
      id: 'mixing_service',
      name: 'Transaction Mixing',
      icon: '🔀',
      description: 'Anonymous transaction routing',
      resourceUsage: 'Medium',
      recommended: true
    },
    {
      id: 'dex_relay',
      name: 'DEX Relay',
      icon: '🏪',
      description: 'Facilitate P2P trades',
      resourceUsage: 'High',
      recommended: deviceType === 'computer'
    },
    {
      id: 'network_relay',
      name: 'Network Relay',
      icon: '🌐',
      description: 'Forward messages/transactions',
      resourceUsage: 'Low',
      recommended: true
    },
    {
      id: 'governance',
      name: 'Governance',
      icon: '🗳️',
      description: 'Vote on network proposals',
      resourceUsage: 'Low',
      recommended: true
    },
    {
      id: 'vault_relay',
      name: 'Vault Relay',
      icon: '📡',
      description: 'Route Quantum Vault transfers',
      resourceUsage: 'Medium',
      recommended: deviceType === 'computer'
    }
  ];

  const currentReq = deviceRequirements[deviceType];

  const handleLaunchMasternode = async () => {
    if (!masternodesEnabled) {
      setError('Masternodes are not yet enabled. Wait for 18 months after first PoW block.');
      return;
    }

    if (balance < collateralRequired) {
      setError(`Insufficient balance. ${collateralRequired} WEPO required for masternode collateral.`);
      return;
    }

    if (selectedServices.length < currentReq.services) {
      setError(`Please select at least ${currentReq.services} services for ${deviceType} masternode.`);
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      // Simulate masternode launch process
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      setMasternodeActive(true);
      setSuccess(`${deviceType === 'computer' ? 'Computer' : 'Mobile'} masternode launched successfully!`);
      
      // Start mock stats tracking
      setMasternodeStats({
        uptime: 0.5,
        dailyEarnings: 0.2,
        servicesActive: selectedServices.length,
        lastReward: 0.1,
        totalEarned: 0.2
      });
      
    } catch (error) {
      setError('Masternode launch failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleStopMasternode = async () => {
    setIsLoading(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 1500));
      setMasternodeActive(false);
      setSuccess('Masternode stopped successfully.');
      setMasternodeStats({
        uptime: 0,
        dailyEarnings: 0,
        servicesActive: 0,
        lastReward: 0,
        totalEarned: masternodeStats.totalEarned
      });
    } catch (error) {
      setError('Failed to stop masternode.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleServiceToggle = (serviceId) => {
    if (selectedServices.includes(serviceId)) {
      if (selectedServices.length > currentReq.services) {
        setSelectedServices(selectedServices.filter(id => id !== serviceId));
      }
    } else {
      setSelectedServices([...selectedServices, serviceId]);
    }
  };
      return;
    }

    if (!isValidIP(serverIP)) {
      setError('Please enter a valid IP address');
      return;
    }

    setIsLoading(true);
    try {
      // Simulate masternode setup process
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      setSuccess(`Masternode successfully configured! IP: ${serverIP}:${serverPort}`);
      setServerIP('');
    } catch (error) {
      setError('Masternode setup failed. Please check your server configuration.');
    } finally {
      setIsLoading(false);
    }
  };

  const isValidIP = (ip) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
  };

  const calculateMasternodeRewards = () => {
    const totalAPR = masternodeAPR + mixingFeeAPR;
    return (collateralRequired * totalAPR / 100);
  };

  if (!masternodesEnabled) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3 mb-6">
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <ArrowLeft size={24} />
          </button>
          <div className="flex items-center gap-2">
            <Clock className="h-6 w-6 text-gray-500" />
            <h2 className="text-xl font-semibold text-white">Masternodes</h2>
          </div>
        </div>

        <div className="text-center py-12">
          <Server className="h-16 w-16 text-gray-500 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">Masternodes Not Yet Available</h3>
          <p className="text-gray-400 mb-4">
            Masternode functionality will be unlocked 18 months after the first PoW block is mined.
          </p>
          <p className="text-sm text-purple-300">
            This ensures the network has sufficient time to establish itself before deploying advanced infrastructure.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={24} />
        </button>
        <div className="flex items-center gap-2">
          <Server className="h-6 w-6 text-purple-400" />
          <h2 className="text-xl font-semibold text-white">Masternode Setup</h2>
        </div>
      </div>

      <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30">
        <div className="flex items-center gap-2 mb-2">
          <Shield className="h-4 w-4 text-purple-400" />
          <span className="text-sm font-medium text-purple-200">Network Infrastructure</span>
        </div>
        <p className="text-sm text-gray-300">
          Masternodes provide privacy mixing, DEX relay services, and network stability. 
          They require 10,000 WEPO collateral and a dedicated server.
        </p>
      </div>

      {/* Requirements Check */}
      <div className="bg-gray-700/30 rounded-lg p-4">
        <h3 className="text-white font-medium mb-3">Masternode Requirements</h3>
        <div className="space-y-2 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-gray-400">Collateral Required:</span>
            <span className="text-white font-medium">{collateralRequired.toLocaleString()} WEPO</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-400">Your Balance:</span>
            <span className={`font-medium ${balance >= collateralRequired ? 'text-green-400' : 'text-red-400'}`}>
              {balance.toLocaleString()} WEPO
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-400">Dedicated Server:</span>
            <span className="text-yellow-400 font-medium">Required</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-400">Static IP Address:</span>
            <span className="text-yellow-400 font-medium">Required</span>
          </div>
        </div>
      </div>

      {/* Server Configuration */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            Server IP Address
          </label>
          <div className="relative">
            <input
              type="text"
              value={serverIP}
              onChange={(e) => setServerIP(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pl-12"
              placeholder="192.168.1.100"
            />
            <Globe className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Enter the public IP address of your dedicated server
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            Server Port
          </label>
          <input
            type="number"
            value={serverPort}
            onChange={(e) => setServerPort(e.target.value)}
            className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
            placeholder="22567"
            min="1"
            max="65535"
          />
          <p className="text-xs text-gray-400 mt-1">
            Default WEPO masternode port is 22567
          </p>
        </div>
      </div>

      {/* Rewards Information */}
      <div className="bg-gray-700/30 rounded-lg p-4">
        <h3 className="text-white font-medium mb-3 flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-purple-400" />
          Masternode Rewards
        </h3>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-400">Base APR:</span>
            <div className="text-purple-400 font-medium">{masternodeAPR}%</div>
          </div>
          <div>
            <span className="text-gray-400">Mixing Fees APR:</span>
            <div className="text-purple-400 font-medium">~{mixingFeeAPR}%</div>
          </div>
          <div>
            <span className="text-gray-400">Total APR:</span>
            <div className="text-green-400 font-medium">{masternodeAPR + mixingFeeAPR}%</div>
          </div>
          <div>
            <span className="text-gray-400">Annual Rewards:</span>
            <div className="text-green-400 font-medium">{calculateMasternodeRewards().toLocaleString()} WEPO</div>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-500 rounded-lg p-3 text-red-200 text-sm">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-900/50 border border-green-500 rounded-lg p-3 text-green-200 text-sm">
          {success}
        </div>
      )}

      {/* Server Requirements */}
      <div className="bg-yellow-900/30 rounded-lg p-4 border border-yellow-500/30">
        <div className="flex items-center gap-2 mb-2">
          <AlertCircle className="h-4 w-4 text-yellow-400" />
          <span className="text-sm font-medium text-yellow-200">Server Requirements</span>
        </div>
        <ul className="text-sm text-gray-300 space-y-1">
          <li>• VPS with at least 2GB RAM and 40GB storage</li>
          <li>• Ubuntu 20.04 or CentOS 8 recommended</li>
          <li>• Static IP address with ports 22567 open</li>
          <li>• 99.9% uptime to maximize rewards</li>
          <li>• Regular security updates and monitoring</li>
        </ul>
      </div>

      <button
        onClick={handleSetupMasternode}
        disabled={isLoading || balance < collateralRequired || !serverIP}
        className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        <Server size={20} />
        {isLoading ? 'Setting up Masternode...' : 'Setup Masternode'}
      </button>
    </div>
  );
};

export default MasternodeInterface;