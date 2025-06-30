import React, { useState } from 'react';
import { ArrowRightLeft, ArrowLeft, Bitcoin, AlertTriangle, TrendingUp } from 'lucide-react';

const BtcDexSwap = ({ onClose }) => {
  const [swapType, setSwapType] = useState('buy'); // 'buy' or 'sell'
  const [btcAmount, setBtcAmount] = useState('');
  const [wepoAmount, setWepoAmount] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Mock exchange rate - in real implementation, this would come from the DEX
  const exchangeRate = 1; // 1 BTC = 1 WEPO (for demo)
  const swapFee = 0.001; // 0.1% fee

  const handleAmountChange = (type, value) => {
    if (type === 'btc') {
      setBtcAmount(value);
      setWepoAmount((parseFloat(value) * exchangeRate || 0).toString());
    } else {
      setWepoAmount(value);
      setBtcAmount((parseFloat(value) / exchangeRate || 0).toString());
    }
    setError('');
    setSuccess('');
  };

  const calculateFee = () => {
    const amount = swapType === 'buy' ? parseFloat(btcAmount) : parseFloat(wepoAmount);
    return (amount * swapFee) || 0;
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

    setIsLoading(true);
    try {
      // Simulate atomic swap process
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      setSuccess(`Successfully swapped ${btcAmount} BTC for ${wepoAmount} WEPO!`);
      setBtcAmount('');
      setWepoAmount('');
    } catch (error) {
      setError('Swap failed. Please try again.');
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
            <div className="text-white font-medium">1 BTC = {exchangeRate} WEPO</div>
          </div>
          <div>
            <span className="text-gray-400">Swap Fee:</span>
            <div className="text-white font-medium">{(swapFee * 100).toFixed(1)}%</div>
          </div>
          <div>
            <span className="text-gray-400">Estimated Fee:</span>
            <div className="text-white font-medium">
              {calculateFee().toFixed(8)} {swapType === 'buy' ? 'BTC' : 'WEPO'}
            </div>
          </div>
          <div>
            <span className="text-gray-400">Settlement:</span>
            <div className="text-white font-medium">~10 minutes</div>
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