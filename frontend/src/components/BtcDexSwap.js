import React, { useState, useEffect } from 'react';
import { ArrowRightLeft, ArrowLeft, Bitcoin, AlertTriangle, TrendingUp, Clock, DollarSign, Info } from 'lucide-react';

const BtcDexSwap = ({ onClose }) => {
  const [swapType, setSwapType] = useState('buy'); // 'buy' or 'sell'
  const [btcAmount, setBtcAmount] = useState('');
  const [wepoAmount, setWepoAmount] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [exchangeRate, setExchangeRate] = useState(1);
  const [feeInfo, setFeeInfo] = useState(null);
  const [statistics, setStatistics] = useState(null);
  const [priorityFee, setPriorityFee] = useState(false);
  const [swapHistory, setSwapHistory] = useState([]);
  const [activeSwap, setActiveSwap] = useState(null);
  
  // BTC and WEPO addresses (in real implementation, these would come from wallet)
  const [btcAddress, setBtcAddress] = useState('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
  const [wepoAddress, setWepoAddress] = useState('wepo1test123456789abcdef0123456789abcdef01');

  // Fetch exchange rate and statistics on component mount
  useEffect(() => {
    fetchExchangeRate();
    fetchStatistics();
    fetchSwapHistory();
  }, []);

  // Update amounts when exchange rate changes
  useEffect(() => {
    if (btcAmount && exchangeRate) {
      setWepoAmount((parseFloat(btcAmount) * exchangeRate).toFixed(6));
    }
  }, [exchangeRate, btcAmount]);

  // Fetch fee information when amount changes
  useEffect(() => {
    if (btcAmount && parseFloat(btcAmount) > 0) {
      fetchFeeInfo();
    }
  }, [btcAmount, priorityFee]);

  const fetchExchangeRate = async () => {
    try {
      const response = await fetch('/api/atomic-swap/exchange-rate');
      const data = await response.json();
      setExchangeRate(data.btc_to_wepo);
    } catch (err) {
      console.error('Error fetching exchange rate:', err);
    }
  };

  const fetchFeeInfo = async () => {
    if (!btcAmount || parseFloat(btcAmount) <= 0) return;
    
    try {
      const response = await fetch(`/api/atomic-swap/fees?btc_amount=${btcAmount}&swap_type=btc_to_wepo&priority=${priorityFee}`);
      const data = await response.json();
      setFeeInfo(data.fees);
    } catch (err) {
      console.error('Error fetching fee info:', err);
    }
  };

  const fetchStatistics = async () => {
    try {
      const response = await fetch('/api/atomic-swap/statistics');
      const data = await response.json();
      setStatistics(data.statistics);
    } catch (err) {
      console.error('Error fetching statistics:', err);
    }
  };

  const fetchSwapHistory = async () => {
    try {
      const response = await fetch('/api/atomic-swap/history?limit=5');
      const data = await response.json();
      setSwapHistory(data.history);
    } catch (err) {
      console.error('Error fetching swap history:', err);
    }
  };

  const handleAmountChange = (type, value) => {
    if (type === 'btc') {
      setBtcAmount(value);
      setWepoAmount((parseFloat(value) * exchangeRate || 0).toFixed(6));
    } else {
      setWepoAmount(value);
      setBtcAmount((parseFloat(value) / exchangeRate || 0).toFixed(6));
    }
    setError('');
    setSuccess('');
  };

  const handleSwap = async () => {
    if (!btcAmount || !wepoAmount) {
      setError('Please enter an amount to swap');
      return;
    }

    if (parseFloat(btcAmount) <= 0 || parseFloat(wepoAmount) <= 0) {
      setError('Amount must be greater than 0');
      return;
    }

    if (parseFloat(btcAmount) < 0.001) {
      setError('Minimum swap amount is 0.001 BTC');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      // Initiate atomic swap
      const response = await fetch('/api/atomic-swap/initiate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          swap_type: 'btc_to_wepo',
          btc_amount: parseFloat(btcAmount),
          initiator_btc_address: btcAddress,
          initiator_wepo_address: wepoAddress,
          participant_btc_address: '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', // Mock participant
          participant_wepo_address: 'wepo1participant123456789abcdef0123456789ab'
        }),
      });

      const data = await response.json();
      
      if (response.ok && data.success) {
        setActiveSwap(data);
        setSuccess(`Swap initiated successfully! Swap ID: ${data.swap_id}`);
        
        // Reset form
        setBtcAmount('');
        setWepoAmount('');
        setFeeInfo(null);
        
        // Refresh data
        fetchStatistics();
        fetchSwapHistory();
      } else {
        setError(data.detail || 'Failed to initiate swap');
      }
    } catch (err) {
      setError('Error initiating swap: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const switchSwapType = () => {
    setSwapType(swapType === 'buy' ? 'sell' : 'buy');
    setBtcAmount('');
    setWepoAmount('');
  };

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
          <ArrowRightLeft className="h-6 w-6 text-blue-400" />
          <h2 className="text-xl font-semibold text-white">BTC ↔ WEPO DEX</h2>
        </div>
      </div>

      <div className="bg-blue-900/30 rounded-lg p-4 border border-blue-500/30">
        <div className="flex items-center gap-2 mb-2">
          <Bitcoin className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium text-blue-200">Decentralized Exchange</span>
        </div>
        <p className="text-sm text-gray-300">
          Swap Bitcoin for WEPO using atomic swaps. Your funds are never held by a third party - 
          the exchange happens directly between you and the network.
        </p>
      </div>

      {/* Swap Type Toggle */}
      <div className="flex bg-gray-700 rounded-lg p-1">
        <button
          onClick={() => setSwapType('buy')}
          className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            swapType === 'buy' 
              ? 'bg-green-600 text-white' 
              : 'text-gray-300 hover:text-white'
          }`}
        >
          Buy WEPO
        </button>
        <button
          onClick={() => setSwapType('sell')}
          className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
            swapType === 'sell' 
              ? 'bg-red-600 text-white' 
              : 'text-gray-300 hover:text-white'
          }`}
        >
          Sell WEPO
        </button>
      </div>

      <div className="space-y-4">
        {/* From Section */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            {swapType === 'buy' ? 'Pay with BTC' : 'Sell WEPO'}
          </label>
          <div className="relative">
            <input
              type="number"
              value={swapType === 'buy' ? btcAmount : wepoAmount}
              onChange={(e) => handleAmountChange(swapType === 'buy' ? 'btc' : 'wepo', e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-20"
              placeholder="0.00000000"
              step="0.00000001"
              min="0"
            />
            <div className="absolute right-3 top-3 text-gray-400 font-medium">
              {swapType === 'buy' ? 'BTC' : 'WEPO'}
            </div>
          </div>
        </div>

        {/* Swap Arrow */}
        <div className="flex justify-center">
          <button
            onClick={switchSwapType}
            className="bg-purple-600 hover:bg-purple-700 p-3 rounded-full transition-colors"
          >
            <ArrowRightLeft className="h-5 w-5 text-white" />
          </button>
        </div>

        {/* To Section */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            {swapType === 'buy' ? 'Receive WEPO' : 'Receive BTC'}
          </label>
          <div className="relative">
            <input
              type="number"
              value={swapType === 'buy' ? wepoAmount : btcAmount}
              onChange={(e) => handleAmountChange(swapType === 'buy' ? 'wepo' : 'btc', e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-20"
              placeholder="0.00000000"
              step="0.00000001"
              min="0"
            />
            <div className="absolute right-3 top-3 text-gray-400 font-medium">
              {swapType === 'buy' ? 'WEPO' : 'BTC'}
            </div>
          </div>
        </div>
      </div>

      {/* Market Info */}
      <div className="bg-gray-700/30 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <TrendingUp className="h-4 w-4 text-purple-400" />
          <span className="text-sm font-medium text-white">Market Information</span>
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-400">Exchange Rate:</span>
            <div className="text-white font-medium">1 BTC = {exchangeRate.toFixed(6)} WEPO</div>
          </div>
          <div>
            <span className="text-gray-400">Fee Rate:</span>
            <div className="text-white font-medium">{feeInfo?.fee_percentage || 0.1}%</div>
          </div>
          <div>
            <span className="text-gray-400">Estimated Fee:</span>
            <div className="text-white font-medium">
              {feeInfo ? `${feeInfo.total_fee_btc.toFixed(8)} BTC` : '0.00000000 BTC'}
            </div>
          </div>
          <div>
            <span className="text-gray-400">Settlement:</span>
            <div className="text-white font-medium">
              {priorityFee ? '~1-2 hours' : '~2-4 hours'}
            </div>
          </div>
        </div>
      </div>

      {/* Priority Fee Toggle */}
      <div className="flex items-center justify-between">
        <div>
          <span className="text-white font-medium">Priority Fee</span>
          <p className="text-sm text-gray-400">Get faster confirmation times</p>
        </div>
        <button
          onClick={() => setPriorityFee(!priorityFee)}
          className={`w-12 h-6 rounded-full transition-colors ${
            priorityFee ? 'bg-blue-600' : 'bg-gray-600'
          }`}
        >
          <div className={`w-5 h-5 rounded-full bg-white transition-transform ${
            priorityFee ? 'translate-x-6' : 'translate-x-0.5'
          }`} />
        </button>
      </div>

      {/* Statistics Display */}
      {statistics && (
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-600">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="h-4 w-4 text-green-400" />
            <span className="text-sm font-medium text-white">DEX Statistics</span>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">Total Swaps:</span>
              <div className="text-white font-medium">{statistics.total_swaps}</div>
            </div>
            <div>
              <span className="text-gray-400">Success Rate:</span>
              <div className="text-white font-medium">{(statistics.success_rate * 100).toFixed(1)}%</div>
            </div>
            <div>
              <span className="text-gray-400">BTC Volume:</span>
              <div className="text-white font-medium">{statistics.total_btc_volume.toFixed(4)} BTC</div>
            </div>
            <div>
              <span className="text-gray-400">Active Swaps:</span>
              <div className="text-white font-medium">{statistics.active_swaps}</div>
            </div>
          </div>
        </div>
      )}

      {/* Recent Swaps */}
      {swapHistory.length > 0 && (
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-600">
          <div className="flex items-center gap-2 mb-3">
            <Clock className="h-4 w-4 text-blue-400" />
            <span className="text-sm font-medium text-white">Recent Swaps</span>
          </div>
          <div className="space-y-2">
            {swapHistory.slice(0, 3).map((swap, index) => (
              <div key={index} className="flex items-center justify-between text-sm">
                <div>
                  <span className="text-gray-400">
                    {swap.btc_amount} BTC → {swap.wepo_amount} WEPO
                  </span>
                </div>
                <div className={`px-2 py-1 rounded text-xs ${
                  swap.state === 'redeemed' ? 'bg-green-900/50 text-green-200' :
                  swap.state === 'funded' ? 'bg-blue-900/50 text-blue-200' :
                  swap.state === 'initiated' ? 'bg-yellow-900/50 text-yellow-200' :
                  'bg-gray-900/50 text-gray-200'
                }`}>
                  {swap.state}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Swap Status */}
      {activeSwap && (
        <div className="bg-blue-900/30 rounded-lg p-4 border border-blue-500/30">
          <div className="flex items-center gap-2 mb-3">
            <Info className="h-4 w-4 text-blue-400" />
            <span className="text-sm font-medium text-blue-200">Active Swap</span>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-400">Swap ID:</span>
              <span className="text-white font-mono">{activeSwap.swap_id.slice(0, 16)}...</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Status:</span>
              <span className="text-blue-200">{activeSwap.state}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">BTC HTLC:</span>
              <span className="text-white font-mono">{activeSwap.btc_htlc_address}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">WEPO HTLC:</span>
              <span className="text-white font-mono">{activeSwap.wepo_htlc_address}</span>
            </div>
          </div>
        </div>
      )}

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

      {/* Warning */}
      <div className="bg-yellow-900/30 rounded-lg p-4 border border-yellow-500/30">
        <div className="flex items-center gap-2 mb-2">
          <AlertTriangle className="h-4 w-4 text-yellow-400" />
          <span className="text-sm font-medium text-yellow-200">Important Notice</span>
        </div>
        <p className="text-sm text-gray-300">
          This is a trustless atomic swap. Make sure you have sufficient BTC in your external wallet 
          and that your transaction fees are properly set. The swap cannot be reversed once initiated.
        </p>
      </div>

      <button
        onClick={handleSwap}
        disabled={isLoading || !btcAmount || !wepoAmount}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        <ArrowRightLeft size={20} />
        {isLoading ? 'Processing Swap...' : `Swap ${swapType === 'buy' ? 'BTC for WEPO' : 'WEPO for BTC'}`}
      </button>
    </div>
  );
};

export default BtcDexSwap;