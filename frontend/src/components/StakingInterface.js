import React, { useState } from 'react';
import { Coins, ArrowLeft, Lock, TrendingUp, AlertCircle, Clock } from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';

const StakingInterface = ({ onClose }) => {
  const { balance, posEnabled } = useWallet();
  const [stakeAmount, setStakeAmount] = useState('');
  const [lockPeriod, setLockPeriod] = useState('1'); // years
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Mock staking data - in real implementation, this would come from the blockchain
  const minimumStake = 1000;
  const baseAPR = 1; // 1% base APR
  const lockPeriodBonus = 0.5; // 0.5% per year locked

  const calculateAPR = () => {
    return baseAPR + (lockPeriodBonus * parseInt(lockPeriod));
  };

  const calculateRewards = () => {
    const amount = parseFloat(stakeAmount) || 0;
    const apr = calculateAPR();
    return (amount * apr / 100);
  };

  const handleStake = async () => {
    if (!posEnabled) {
      setError('Proof of Stake is not yet enabled. Wait for 18 months after first PoW block.');
      return;
    }

    if (!stakeAmount || parseFloat(stakeAmount) < minimumStake) {
      setError(`Minimum stake amount is ${minimumStake} WEPO`);
      return;
    }

    if (parseFloat(stakeAmount) > balance) {
      setError('Insufficient balance for staking');
      return;
    }

    setIsLoading(true);
    try {
      // Simulate staking process
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      setSuccess(`Successfully staked ${stakeAmount} WEPO for ${lockPeriod} year(s)!`);
      setStakeAmount('');
    } catch (error) {
      setError('Staking failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const setMaxStake = () => {
    // Reserve small amount for transactions
    const maxAmount = Math.max(0, balance - 1);
    setStakeAmount(maxAmount.toString());
  };

  if (!posEnabled) {
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
            <Lock className="h-6 w-6 text-gray-500" />
            <h2 className="text-xl font-semibold text-white">Proof of Stake</h2>
          </div>
          <div className="text-xs text-gray-400 ml-10">Activates at Block 131,400</div>
        </div>

        <div className="text-center py-12">
          <Clock className="h-16 w-16 text-gray-500 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">Staking Not Yet Available</h3>
          <p className="text-gray-400 mb-4">
            Proof of Stake and staking features will be unlocked 18 months after the first PoW block is mined.
          </p>
          <p className="text-sm text-purple-300">
            This ensures the network has sufficient time to establish itself through mining before transitioning to hybrid consensus.
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
          <Coins className="h-6 w-6 text-green-400" />
          <h2 className="text-xl font-semibold text-white">Proof of Stake Staking</h2>
        </div>
      </div>

      <div className="bg-green-900/30 rounded-lg p-4 border border-green-500/30">
        <div className="flex items-center gap-2 mb-2">
          <TrendingUp className="h-4 w-4 text-green-400" />
          <span className="text-sm font-medium text-green-200">Earn Rewards</span>
        </div>
        <p className="text-sm text-gray-300">
          Stake your WEPO to help secure the network and earn rewards. Longer lock periods provide higher APR.
        </p>
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            Stake Amount (WEPO)
          </label>
          <div className="relative">
            <input
              type="number"
              value={stakeAmount}
              onChange={(e) => setStakeAmount(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-20"
              placeholder="1000.0000"
              step="0.0001"
              min={minimumStake}
            />
            <button
              type="button"
              onClick={setMaxStake}
              className="absolute right-2 top-2 bg-green-600 hover:bg-green-700 text-white text-xs px-3 py-1 rounded transition-colors"
            >
              MAX
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Minimum: {minimumStake} WEPO | Available: {balance.toFixed(4)} WEPO
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            Lock Period
          </label>
          <select
            value={lockPeriod}
            onChange={(e) => setLockPeriod(e.target.value)}
            className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
          >
            <option value="1">1 Year (1.5% APR)</option>
            <option value="2">2 Years (2.0% APR)</option>
            <option value="3">3 Years (2.5% APR)</option>
            <option value="4">4 Years (3.0% APR)</option>
            <option value="5">5 Years (3.5% APR)</option>
          </select>
          <p className="text-xs text-gray-400 mt-1">
            Longer lock periods provide higher annual percentage rates
          </p>
        </div>
      </div>

      {/* Staking Rewards Calculator */}
      <div className="bg-gray-700/30 rounded-lg p-4">
        <h3 className="text-white font-medium mb-3">Staking Rewards Calculator</h3>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-400">Stake Amount:</span>
            <div className="text-white font-medium">{stakeAmount || '0'} WEPO</div>
          </div>
          <div>
            <span className="text-gray-400">Lock Period:</span>
            <div className="text-white font-medium">{lockPeriod} Year(s)</div>
          </div>
          <div>
            <span className="text-gray-400">APR:</span>
            <div className="text-green-400 font-medium">{calculateAPR().toFixed(1)}%</div>
          </div>
          <div>
            <span className="text-gray-400">Annual Rewards:</span>
            <div className="text-green-400 font-medium">{calculateRewards().toFixed(4)} WEPO</div>
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

      {/* Important Information */}
      <div className="bg-yellow-900/30 rounded-lg p-4 border border-yellow-500/30">
        <div className="flex items-center gap-2 mb-2">
          <AlertCircle className="h-4 w-4 text-yellow-400" />
          <span className="text-sm font-medium text-yellow-200">Important Information</span>
        </div>
        <ul className="text-sm text-gray-300 space-y-1">
          <li>• Staked WEPO will be locked for the selected period</li>
          <li>• Rewards are distributed automatically to your wallet</li>
          <li>• Early withdrawal is not possible during lock period</li>
          <li>• Staking helps secure the WEPO network</li>
        </ul>
      </div>

      <button
        onClick={handleStake}
        disabled={isLoading || !stakeAmount || parseFloat(stakeAmount) < minimumStake}
        className="w-full bg-green-600 hover:bg-green-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        <Coins size={20} />
        {isLoading ? 'Staking...' : `Stake ${stakeAmount || '0'} WEPO`}
      </button>
    </div>
  );
};

export default StakingInterface;