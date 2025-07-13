import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Lock, 
  Eye, 
  EyeOff, 
  ArrowDown, 
  ArrowUp, 
  Settings,
  AlertCircle,
  CheckCircle,
  Plus,
  TrendingUp,
  Zap,
  DollarSign
} from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';

const QuantumVault = ({ onClose }) => {
  const { wallet } = useWallet();
  
  // State management
  const [vaults, setVaults] = useState([]);
  const [selectedVault, setSelectedVault] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Form states
  const [depositAmount, setDepositAmount] = useState('');
  const [withdrawAmount, setWithdrawAmount] = useState('');
  const [withdrawAddress, setWithdrawAddress] = useState('');
  
  // UI states
  const [showBalance, setShowBalance] = useState(false);
  const [autoDepositEnabled, setAutoDepositEnabled] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview', 'deposit', 'withdraw', 'settings', 'ghost'
  
  // Ghost Transfer states
  const [ghostTransferMode, setGhostTransferMode] = useState('send'); // 'send', 'receive', 'history'
  const [targetVaultId, setTargetVaultId] = useState('');
  const [ghostAmount, setGhostAmount] = useState('');
  const [privacyLevel, setPrivacyLevel] = useState('maximum');
  const [hideAmount, setHideAmount] = useState(true);
  const [pendingGhostTransfers, setPendingGhostTransfers] = useState([]);
  const [ghostHistory, setGhostHistory] = useState([]);
  
  const currentAddress = wallet?.address;
  const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  useEffect(() => {
    if (currentAddress) {
      loadWalletVaults();
    }
  }, [currentAddress]);

  const loadWalletVaults = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${backendUrl}/api/vault/wallet/${currentAddress}`);
      const data = await response.json();
      
      if (data.success) {
        setVaults(data.vaults || []);
        if (data.vaults && data.vaults.length > 0) {
          setSelectedVault(data.vaults[0]);
          setAutoDepositEnabled(data.vaults[0].auto_deposit_enabled);
        }
      } else {
        setError('Failed to load vaults');
      }
    } catch (err) {
      console.error('Error loading vaults:', err);
      setError('Failed to connect to vault system');
    } finally {
      setLoading(false);
    }
  };

  const createQuantumVault = async () => {
    try {
      setLoading(true);
      setError('');
      
      const response = await fetch(`${backendUrl}/api/vault/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          wallet_address: currentAddress
        }),
      });

      const data = await response.json();
      
      if (data.success) {
        setSuccess('Quantum Vault created successfully! Ultimate privacy enabled.');
        await loadWalletVaults();
      } else {
        setError(data.message || 'Failed to create vault');
      }
    } catch (err) {
      console.error('Error creating vault:', err);
      setError('Failed to create vault');
    } finally {
      setLoading(false);
    }
  };

  const depositToVault = async () => {
    if (!selectedVault || !depositAmount || parseFloat(depositAmount) <= 0) {
      setError('Please enter a valid deposit amount');
      return;
    }

    try {
      setLoading(true);
      setError('');
      
      const response = await fetch(`${backendUrl}/api/vault/deposit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          vault_id: selectedVault.vault_id,
          amount: parseFloat(depositAmount),
          source_type: 'manual'
        }),
      });

      const data = await response.json();
      
      if (data.success) {
        setSuccess(`Successfully deposited ${depositAmount} WEPO to Quantum Vault`);
        setDepositAmount('');
        await loadWalletVaults();
      } else {
        setError(data.message || 'Failed to deposit to vault');
      }
    } catch (err) {
      console.error('Error depositing to vault:', err);
      setError('Failed to deposit to vault');
    } finally {
      setLoading(false);
    }
  };

  const withdrawFromVault = async () => {
    if (!selectedVault || !withdrawAmount || !withdrawAddress) {
      setError('Please fill in all withdrawal fields');
      return;
    }

    if (parseFloat(withdrawAmount) <= 0) {
      setError('Please enter a valid withdrawal amount');
      return;
    }

    try {
      setLoading(true);
      setError('');
      
      const response = await fetch(`${backendUrl}/api/vault/withdraw`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          vault_id: selectedVault.vault_id,
          amount: parseFloat(withdrawAmount),
          destination_address: withdrawAddress
        }),
      });

      const data = await response.json();
      
      if (data.success) {
        setSuccess(`Successfully withdrew ${withdrawAmount} WEPO from Quantum Vault`);
        setWithdrawAmount('');
        setWithdrawAddress('');
        await loadWalletVaults();
      } else {
        setError(data.message || 'Failed to withdraw from vault');
      }
    } catch (err) {
      console.error('Error withdrawing from vault:', err);
      setError('Failed to withdraw from vault');
    } finally {
      setLoading(false);
    }
  };

  const toggleAutoDeposit = async () => {
    if (!selectedVault) return;

    try {
      setLoading(true);
      setError('');
      
      const endpoint = autoDepositEnabled ? 'disable' : 'enable';
      const requestBody = autoDepositEnabled 
        ? { wallet_address: currentAddress }
        : { wallet_address: currentAddress, vault_id: selectedVault.vault_id };
      
      const response = await fetch(`${backendUrl}/api/vault/auto-deposit/${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      const data = await response.json();
      
      if (data.success) {
        setAutoDepositEnabled(!autoDepositEnabled);
        setSuccess(autoDepositEnabled 
          ? 'Auto-deposit disabled - incoming WEPO will go to regular wallet'
          : 'Auto-deposit enabled - all incoming WEPO will be privately stored'
        );
        await loadWalletVaults();
      } else {
        setError(data.message || 'Failed to toggle auto-deposit');
      }
    } catch (err) {
      console.error('Error toggling auto-deposit:', err);
      setError('Failed to toggle auto-deposit');
    } finally {
      setLoading(false);
    }
  };

  const formatBalance = (balance) => {
    return showBalance ? balance.toFixed(6) : '••••••';
  };

  const renderOverview = () => (
    <div className="space-y-6">
      {/* Vault Status */}
      <div className="bg-gradient-to-r from-indigo-600 to-purple-600 rounded-xl p-6 text-white">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="h-8 w-8" />
          <div>
            <h3 className="text-xl font-bold">Quantum Vault</h3>
            <p className="text-sm text-indigo-100">Ultimate Privacy Protection</p>
          </div>
        </div>
        
        {selectedVault && (
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-sm text-indigo-200">Private Balance</span>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold">{formatBalance(selectedVault.private_balance)} WEPO</span>
                <button
                  onClick={() => setShowBalance(!showBalance)}
                  className="text-indigo-200 hover:text-white"
                >
                  {showBalance ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
            </div>
            <div>
              <span className="text-sm text-indigo-200">Privacy Level</span>
              <div className="text-lg font-semibold capitalize">{selectedVault.privacy_level}</div>
            </div>
          </div>
        )}
      </div>

      {/* Auto-Deposit Status */}
      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Zap className={`h-5 w-5 ${autoDepositEnabled ? 'text-green-400' : 'text-gray-400'}`} />
            <div>
              <h4 className="text-white font-medium">Auto-Deposit</h4>
              <p className="text-sm text-gray-400">
                {autoDepositEnabled 
                  ? 'All incoming WEPO automatically goes to vault'
                  : 'Incoming WEPO goes to regular wallet'
                }
              </p>
            </div>
          </div>
          <div className={`w-3 h-3 rounded-full ${autoDepositEnabled ? 'bg-green-400' : 'bg-gray-400'}`}></div>
        </div>
      </div>

      {/* Statistics */}
      {selectedVault && (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="h-4 w-4 text-green-400" />
              <span className="text-sm text-gray-400">Total Deposits</span>
            </div>
            <div className="text-lg font-semibold text-white">
              {selectedVault.statistics.total_deposits.toFixed(6)} WEPO
            </div>
          </div>
          
          <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <DollarSign className="h-4 w-4 text-blue-400" />
              <span className="text-sm text-gray-400">Transactions</span>
            </div>
            <div className="text-lg font-semibold text-white">
              {selectedVault.transaction_count}
            </div>
          </div>

          <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
            <div className="flex items-center gap-2 mb-2">
              <Lock className="h-4 w-4 text-purple-400" />
              <span className="text-sm text-gray-400">Privacy</span>
            </div>
            <div className="text-lg font-semibold text-green-400">Protected</div>
          </div>
        </div>
      )}

      {/* Quick Actions */}
      <div className="grid grid-cols-2 gap-4">
        <button
          onClick={() => setActiveTab('deposit')}
          className="bg-green-600 hover:bg-green-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          <ArrowDown size={20} />
          Deposit WEPO
        </button>
        <button
          onClick={() => setActiveTab('withdraw')}
          className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          <ArrowUp size={20} />
          Withdraw WEPO
        </button>
      </div>
    </div>
  );

  const renderDeposit = () => (
    <div className="space-y-6">
      <div className="bg-green-900/30 rounded-lg p-4 border border-green-500/30">
        <div className="flex items-center gap-2 mb-2">
          <ArrowDown className="h-4 w-4 text-green-400" />
          <span className="text-sm font-medium text-green-200">Deposit to Quantum Vault</span>
        </div>
        <p className="text-sm text-gray-300">
          Deposits are immediately protected with zk-STARK privacy technology.
        </p>
      </div>

      <div>
        <label className="block text-sm font-medium text-purple-200 mb-2">
          WEPO Amount
        </label>
        <input
          type="number"
          value={depositAmount}
          onChange={(e) => setDepositAmount(e.target.value)}
          className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
          placeholder="0.000000"
          step="0.000001"
          min="0"
        />
      </div>

      <button
        onClick={depositToVault}
        disabled={loading || !depositAmount || parseFloat(depositAmount) <= 0 || !selectedVault}
        className="w-full bg-green-600 hover:bg-green-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        <ArrowDown size={20} />
        {loading ? 'Processing...' : 'Deposit to Vault'}
      </button>
    </div>
  );

  const renderWithdraw = () => (
    <div className="space-y-6">
      <div className="bg-blue-900/30 rounded-lg p-4 border border-blue-500/30">
        <div className="flex items-center gap-2 mb-2">
          <ArrowUp className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium text-blue-200">Withdraw from Quantum Vault</span>
        </div>
        <p className="text-sm text-gray-300">
          Withdrawals maintain privacy until funds reach destination address.
        </p>
      </div>

      <div>
        <label className="block text-sm font-medium text-purple-200 mb-2">
          WEPO Amount
        </label>
        <input
          type="number"
          value={withdrawAmount}
          onChange={(e) => setWithdrawAmount(e.target.value)}
          className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
          placeholder="0.000000"
          step="0.000001"
          min="0"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-purple-200 mb-2">
          Destination Address
        </label>
        <input
          type="text"
          value={withdrawAddress}
          onChange={(e) => setWithdrawAddress(e.target.value)}
          className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
          placeholder="wepo1..."
        />
      </div>

      <button
        onClick={withdrawFromVault}
        disabled={loading || !withdrawAmount || !withdrawAddress || !selectedVault}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        <ArrowUp size={20} />
        {loading ? 'Processing...' : 'Withdraw from Vault'}
      </button>
    </div>
  );

  const renderSettings = () => (
    <div className="space-y-6">
      <div className="bg-purple-900/30 rounded-lg p-4 border border-purple-500/30">
        <div className="flex items-center gap-2 mb-2">
          <Settings className="h-4 w-4 text-purple-400" />
          <span className="text-sm font-medium text-purple-200">Vault Settings</span>
        </div>
        <p className="text-sm text-gray-300">
          Configure auto-deposit and privacy preferences.
        </p>
      </div>

      {/* Auto-Deposit Toggle */}
      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-white font-medium mb-1">Auto-Deposit</h4>
            <p className="text-sm text-gray-400">
              Automatically deposit all incoming WEPO to vault
            </p>
          </div>
          <button
            onClick={toggleAutoDeposit}
            disabled={loading || !selectedVault}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              autoDepositEnabled ? 'bg-green-600' : 'bg-gray-600'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                autoDepositEnabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>

      {/* Privacy Information */}
      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
        <h4 className="text-white font-medium mb-3">Privacy Features</h4>
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            <span className="text-gray-300">zk-STARK privacy protection</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            <span className="text-gray-300">Hidden balance storage</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            <span className="text-gray-300">Private transaction history</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            <span className="text-gray-300">Auto-deposit functionality</span>
          </div>
        </div>
      </div>
    </div>
  );

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return renderOverview();
      case 'deposit':
        return renderDeposit();
      case 'withdraw':
        return renderWithdraw();
      case 'settings':
        return renderSettings();
      default:
        return renderOverview();
    }
  };

  if (loading && vaults.length === 0) {
    return (
      <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div className="bg-gray-800 rounded-lg p-8 max-w-md w-full mx-4">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-500 mx-auto"></div>
            <p className="text-white mt-4">Loading Quantum Vault...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="border-b border-gray-700 p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-6 w-6 text-purple-500" />
              <h2 className="text-xl font-bold text-white">Quantum Vault</h2>
            </div>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6">
          {/* Error/Success Messages */}
          {error && (
            <div className="bg-red-900/30 border border-red-500/30 rounded-lg p-4 mb-6 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-400" />
              <span className="text-red-200">{error}</span>
            </div>
          )}
          
          {success && (
            <div className="bg-green-900/30 border border-green-500/30 rounded-lg p-4 mb-6 flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              <span className="text-green-200">{success}</span>
            </div>
          )}

          {/* No Vault State */}
          {vaults.length === 0 && !loading && (
            <div className="text-center py-8">
              <Shield className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">No Quantum Vault</h3>
              <p className="text-gray-400 mb-6">
                Create a Quantum Vault to enable ultimate privacy for your WEPO holdings.
              </p>
              <button
                onClick={createQuantumVault}
                disabled={loading}
                className="bg-purple-600 hover:bg-purple-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2 mx-auto"
              >
                <Plus size={20} />
                {loading ? 'Creating...' : 'Create Quantum Vault'}
              </button>
            </div>
          )}

          {/* Vault Interface */}
          {vaults.length > 0 && (
            <>
              {/* Tab Navigation */}
              <div className="flex bg-gray-700 rounded-lg p-1 mb-6">
                <button
                  onClick={() => setActiveTab('overview')}
                  className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                    activeTab === 'overview' 
                      ? 'bg-purple-600 text-white' 
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  Overview
                </button>
                <button
                  onClick={() => setActiveTab('deposit')}
                  className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                    activeTab === 'deposit' 
                      ? 'bg-purple-600 text-white' 
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  Deposit
                </button>
                <button
                  onClick={() => setActiveTab('withdraw')}
                  className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                    activeTab === 'withdraw' 
                      ? 'bg-purple-600 text-white' 
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  Withdraw
                </button>
                <button
                  onClick={() => setActiveTab('settings')}
                  className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                    activeTab === 'settings' 
                      ? 'bg-purple-600 text-white' 
                      : 'text-gray-300 hover:text-white'
                  }`}
                >
                  Settings
                </button>
              </div>

              {/* Tab Content */}
              {renderTabContent()}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default QuantumVault;