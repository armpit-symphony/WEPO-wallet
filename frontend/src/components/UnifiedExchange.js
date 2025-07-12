import React, { useState, useEffect } from 'react';
import { 
  ArrowRightLeft, 
  ArrowLeft, 
  Bitcoin, 
  AlertTriangle, 
  TrendingUp, 
  Clock, 
  DollarSign, 
  Info,
  Package,
  Coins,
  FileText,
  Image,
  Home,
  Car,
  Palette
} from 'lucide-react';
import { useWallet } from '../contexts/WalletContext';

const UnifiedExchange = ({ onBack }) => {
  const { wallet } = useWallet();
  
  // Get current wallet address
  const currentAddress = wallet?.wepo?.address;
  const btcAddress = wallet?.btc?.address;
  
  const [activeTab, setActiveTab] = useState('btc'); // 'btc', 'rwa', or 'liquidity'
  const [swapType, setSwapType] = useState('buy'); // 'buy' or 'sell'
  const [btcAmount, setBtcAmount] = useState('');
  const [wepoAmount, setWepoAmount] = useState('');
  const [selectedToken, setSelectedToken] = useState(null);
  const [tokenAmount, setTokenAmount] = useState('');
  const [tradeableTokens, setTradeableTokens] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [exchangeRate, setExchangeRate] = useState(1);
  const [rwaRates, setRwaRates] = useState({});
  const [feeInfo, setFeeInfo] = useState(null);
  const [statistics, setStatistics] = useState(null);
  const [priorityFee, setPriorityFee] = useState(false);
  const [swapHistory, setSwapHistory] = useState([]);
  // State for liquidity provision
  const [liquidityBtcAmount, setLiquidityBtcAmount] = useState('');
  const [liquidityWepoAmount, setLiquidityWepoAmount] = useState('');
  const [poolStats, setPoolStats] = useState(null);
  
  // BTC address from wallet (remove the hardcoded one)
  // const [btcAddress, setBtcAddress] = useState('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');

  useEffect(() => {
    fetchExchangeRate();
    fetchFeeInfo();
    fetchStatistics();
    fetchTradeableTokens();
    fetchPoolStats();
  }, []);

  // Update amounts when exchange rate changes
  useEffect(() => {
    if (activeTab === 'btc' && btcAmount && exchangeRate) {
      setWepoAmount((parseFloat(btcAmount) * exchangeRate).toFixed(6));
    }
  }, [exchangeRate, btcAmount, activeTab]);

  // Update RWA amounts when token or amount changes
  useEffect(() => {
    if (activeTab === 'rwa' && selectedToken && tokenAmount) {
      const rate = rwaRates[selectedToken.token_id]?.rate_wepo_per_token || 1;
      setWepoAmount((parseFloat(tokenAmount) * rate).toFixed(8));
    }
  }, [selectedToken, tokenAmount, rwaRates, activeTab]);

  const fetchExchangeRate = async () => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/swap/rate`);
      const data = await response.json();
      
      if (data.pool_exists) {
        setExchangeRate(data.btc_to_wepo);
        setStatistics({
          btc_reserve: data.btc_reserve,
          wepo_reserve: data.wepo_reserve,
          total_liquidity: data.total_liquidity_shares,
          fee_rate: data.fee_rate
        });
      } else {
        setExchangeRate(null);
        setError('No liquidity pool exists yet. You can create the market by adding liquidity.');
      }
    } catch (err) {
      console.error('Error fetching exchange rate:', err);
      setError('Failed to fetch market data');
    }
  };

  const fetchFeeInfo = async () => {
    if (!btcAmount || parseFloat(btcAmount) <= 0) return;
    
    try {
      // For internal swaps, fee is simple 0.1%
      const fee = parseFloat(btcAmount) * 0.001; // 0.1% fee
      setFeeInfo({
        total_fee: fee,
        network_fee: fee * 0.5,
        platform_fee: fee * 0.5,
        priority_fee: priorityFee ? fee * 0.2 : 0
      });
    } catch (err) {
      console.error('Error calculating fees:', err);
    }
  };

  const fetchTradeableTokens = async () => {
    try {
      const response = await fetch('/api/rwa/tokens/tradeable');
      const data = await response.json();
      if (data.success) {
        setTradeableTokens(data.tokens);
      }
    } catch (err) {
      console.error('Error fetching tradeable tokens:', err);
    }
  };

  const fetchStatistics = async () => {
    try {
      // For internal swaps, provide simple statistics
      setStatistics({
        total_swaps_24h: 12,
        total_volume_24h: 1.234,
        average_swap_size: 0.103,
        current_rate: exchangeRate,
        last_updated: new Date().toISOString()
      });
    } catch (err) {
      console.error('Error loading statistics:', err);
    }
  };

  const fetchPoolStats = async () => {
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      const response = await fetch(`${backendUrl}/api/liquidity/stats`);
      const data = await response.json();
      setPoolStats(data);
    } catch (err) {
      console.error('Error fetching pool stats:', err);
    }
  };

  const handleAddLiquidity = async () => {
    if (!liquidityBtcAmount || !liquidityWepoAmount) {
      setError('Please enter both BTC and WEPO amounts');
      return;
    }

    if (parseFloat(liquidityBtcAmount) <= 0 || parseFloat(liquidityWepoAmount) <= 0) {
      setError('Amounts must be greater than 0');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      
      const response = await fetch(`${backendUrl}/api/liquidity/add`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          wallet_address: currentAddress,
          btc_amount: parseFloat(liquidityBtcAmount),
          wepo_amount: parseFloat(liquidityWepoAmount)
        }),
      });

      const data = await response.json();
      
      if (response.ok && data.status === 'success') {
        if (data.pool_created) {
          setSuccess(`Market created! You provided the initial liquidity. Price set at ${data.market_price.toFixed(6)} WEPO per BTC.`);
        } else {
          setSuccess(`Liquidity added successfully! You received ${data.shares_minted.toFixed(6)} LP shares.`);
        }
        
        // Clear form
        setLiquidityBtcAmount('');
        setLiquidityWepoAmount('');
        
        // Refresh data
        fetchExchangeRate();
        fetchPoolStats();
      } else {
        setError(data.detail || 'Failed to add liquidity');
      }
    } catch (err) {
      console.error('Error adding liquidity:', err);
      setError('Failed to add liquidity');
    } finally {
      setIsLoading(false);
    }
  };

  const getAssetIcon = (assetType) => {
    switch (assetType) {
      case 'document': return <FileText className="h-5 w-5" />;
      case 'image': return <Image className="h-5 w-5" />;
      case 'property': return <Home className="h-5 w-5" />;
      case 'vehicle': return <Car className="h-5 w-5" />;
      case 'artwork': return <Palette className="h-5 w-5" />;
      default: return <Package className="h-5 w-5" />;
    }
  };

  const handleBtcSwap = async () => {
    if (!btcAmount) {
      setError('Please enter an amount to swap');
      return;
    }

    if (parseFloat(btcAmount) <= 0) {
      setError('Amount must be greater than 0');
      return;
    }

    if (!exchangeRate) {
      setError('No liquidity pool exists. Add liquidity to create the market.');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';
      
      // Determine swap direction and currency
      const fromCurrency = swapType === 'buy' ? 'BTC' : 'WEPO';
      const inputAmount = swapType === 'buy' ? parseFloat(btcAmount) : parseFloat(wepoAmount);
      
      const response = await fetch(`${backendUrl}/api/swap/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          wallet_address: currentAddress,
          from_currency: fromCurrency,
          input_amount: inputAmount
        }),
      });

      const data = await response.json();
      
      if (response.ok && data.status === 'completed') {
        setSuccess(`Swap completed! Exchanged ${data.input_amount} ${data.from_currency} for ${data.output_amount} ${data.to_currency}. Fee: ${data.fee_amount} ${data.from_currency}`);
        
        // Update exchange rate with new market price
        setExchangeRate(data.market_price);
        
        // Clear form
        setBtcAmount('');
        setWepoAmount('');
        
        // Refresh market data
        fetchExchangeRate();
        
        // TODO: Refresh wallet balances
        
        // Reset form
        setBtcAmount('');
        setWepoAmount('');
        setFeeInfo(null);
        
        // Refresh data
        fetchStatistics();
      } else {
        setError(data.detail || 'Failed to initiate swap');
      }
    } catch (err) {
      setError('Error initiating swap: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRwaTrade = async () => {
    if (!selectedToken || !tokenAmount || !wepoAmount) {
      setError('Please select a token and enter amounts');
      return;
    }

    if (parseFloat(tokenAmount) <= 0 || parseFloat(wepoAmount) <= 0) {
      setError('Amount must be greater than 0');
      return;
    }

    setIsLoading(true);
    setError('');
    
    try {
      const response = await fetch('/api/dex/rwa-trade', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token_id: selectedToken.token_id,
          trade_type: swapType,
          user_address: currentAddress,
          token_amount: parseFloat(tokenAmount) * Math.pow(10, selectedToken.decimals || 8),
          wepo_amount: parseFloat(wepoAmount)
        }),
      });

      const data = await response.json();
      
      if (response.ok && data.success) {
        setSuccess(`${swapType === 'buy' ? 'Purchase' : 'Sale'} completed successfully! Trade ID: ${data.trade_id}`);
        
        // Reset form
        setTokenAmount('');
        setWepoAmount('');
        setSelectedToken(null);
        
        // Refresh data
        fetchTradeableTokens();
        fetchStatistics();
      } else {
        setError(data.detail || 'Failed to execute trade');
      }
    } catch (err) {
      setError('Error executing trade: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const switchSwapType = () => {
    setSwapType(swapType === 'buy' ? 'sell' : 'buy');
    setBtcAmount('');
    setWepoAmount('');
    setTokenAmount('');
  };

  const renderBTCDEX = () => (
    <div className="space-y-6">
      <div className="bg-blue-900/30 rounded-lg p-4 border border-blue-500/30">
        <div className="flex items-center gap-2 mb-2">
          <Bitcoin className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium text-blue-200">Bitcoin DEX</span>
        </div>
        <p className="text-sm text-gray-300">
          Swap Bitcoin for WEPO using atomic swaps. Your funds are never held by a third party.
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
        {/* BTC Amount */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            {swapType === 'buy' ? 'Pay with BTC' : 'Sell WEPO'}
          </label>
          <div className="relative">
            <input
              type="number"
              value={swapType === 'buy' ? btcAmount : wepoAmount}
              onChange={(e) => {
                if (swapType === 'buy') {
                  setBtcAmount(e.target.value);
                  setWepoAmount((parseFloat(e.target.value) * exchangeRate || 0).toFixed(6));
                } else {
                  setWepoAmount(e.target.value);
                  setBtcAmount((parseFloat(e.target.value) / exchangeRate || 0).toFixed(6));
                }
              }}
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

        {/* WEPO Amount */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            {swapType === 'buy' ? 'Receive WEPO' : 'Receive BTC'}
          </label>
          <div className="relative">
            <input
              type="number"
              value={swapType === 'buy' ? wepoAmount : btcAmount}
              onChange={(e) => {
                if (swapType === 'buy') {
                  setWepoAmount(e.target.value);
                  setBtcAmount((parseFloat(e.target.value) / exchangeRate || 0).toFixed(6));
                } else {
                  setBtcAmount(e.target.value);
                  setWepoAmount((parseFloat(e.target.value) * exchangeRate || 0).toFixed(6));
                }
              }}
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
            <div className="text-white font-medium">0.1%</div>
          </div>
        </div>
      </div>

      <button
        onClick={handleBtcSwap}
        disabled={isLoading || !btcAmount || !wepoAmount}
        className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        <Bitcoin size={20} />
        {isLoading ? 'Processing Swap...' : `Swap ${swapType === 'buy' ? 'BTC for WEPO' : 'WEPO for BTC'}`}
      </button>
    </div>
  );

  const renderLiquidityInterface = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-indigo-600 rounded-xl p-6 text-white">
        <div className="flex items-center gap-3 mb-2">
          <Coins className="h-6 w-6" />
          <h3 className="text-xl font-bold">Add Liquidity</h3>
        </div>
        <p className="text-sm text-purple-100">
          {poolStats?.pool_exists 
            ? 'Add liquidity to earn fees from trades'
            : 'Create the market by providing initial liquidity'
          }
        </p>
      </div>

      {/* Pool Statistics */}
      {poolStats?.pool_exists && (
        <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 className="text-lg font-semibold text-white mb-3">Pool Statistics</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">BTC Reserve:</span>
              <div className="text-white font-medium">{poolStats.btc_reserve?.toFixed(6)} BTC</div>
            </div>
            <div>
              <span className="text-gray-400">WEPO Reserve:</span>
              <div className="text-white font-medium">{poolStats.wepo_reserve?.toFixed(2)} WEPO</div>
            </div>
            <div>
              <span className="text-gray-400">Current Price:</span>
              <div className="text-white font-medium">{poolStats.current_price?.toFixed(6)} WEPO/BTC</div>
            </div>
            <div>
              <span className="text-gray-400">Total LPs:</span>
              <div className="text-white font-medium">{poolStats.total_lp_count}</div>
            </div>
          </div>
        </div>
      )}

      {/* Liquidity Form */}
      <div className="space-y-4">
        {/* BTC Amount */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            BTC Amount
          </label>
          <div className="relative">
            <input
              type="number"
              value={liquidityBtcAmount}
              onChange={(e) => {
                setLiquidityBtcAmount(e.target.value);
                // Auto-calculate WEPO amount if pool exists
                if (poolStats?.pool_exists && poolStats.current_price && e.target.value) {
                  setLiquidityWepoAmount((parseFloat(e.target.value) * poolStats.current_price).toFixed(6));
                }
              }}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-16"
              placeholder="0.00000000"
              step="0.00000001"
              min="0"
            />
            <div className="absolute right-3 top-3 text-gray-400 font-medium">BTC</div>
          </div>
        </div>

        {/* WEPO Amount */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            WEPO Amount
          </label>
          <div className="relative">
            <input
              type="number"
              value={liquidityWepoAmount}
              onChange={(e) => setLiquidityWepoAmount(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-20"
              placeholder="0.000000"
              step="0.000001"
              min="0"
            />
            <div className="absolute right-3 top-3 text-gray-400 font-medium">WEPO</div>
          </div>
        </div>

        {/* Pool Creation Notice */}
        {!poolStats?.pool_exists && (
          <div className="bg-yellow-900/30 rounded-lg p-4 border border-yellow-500/30">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="h-4 w-4 text-yellow-400" />
              <span className="text-sm font-medium text-yellow-200">Create Market</span>
            </div>
            <p className="text-sm text-gray-300">
              No liquidity pool exists yet. You will create the market and set the initial BTC/WEPO price ratio.
            </p>
          </div>
        )}

        {/* Add Liquidity Button */}
        <button
          onClick={handleAddLiquidity}
          disabled={isLoading || !liquidityBtcAmount || !liquidityWepoAmount}
          className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          <Coins size={20} />
          {isLoading ? 'Processing...' : 
           poolStats?.pool_exists ? 'Add Liquidity' : 'Create Market'
          }
        </button>
      </div>
    </div>
  );

  const renderRWADEX = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-emerald-600 to-teal-600 rounded-xl p-6 text-white">
        <div className="flex items-center gap-3 mb-2">
          <Package className="h-6 w-6" />
          <h3 className="text-xl font-bold">RWA Token Trading</h3>
        </div>
        <p className="text-sm text-emerald-100">
          Trade Real World Asset tokens for WEPO. Each token represents ownership in physical assets.
        </p>
      </div>

      {/* Token Selection */}
      <div>
        <label className="block text-sm font-medium text-purple-200 mb-2">
          Select RWA Token
        </label>
        <div className="grid grid-cols-1 gap-3 max-h-60 overflow-y-auto">
          {tradeableTokens.map((token) => (
            <button
              key={token.token_id}
              onClick={() => setSelectedToken(token)}
              className={`p-4 rounded-lg border-2 transition-all duration-200 text-left ${
                selectedToken?.token_id === token.token_id
                  ? 'border-emerald-500 bg-emerald-900/30 text-emerald-200'
                  : 'border-gray-600 bg-gray-700/30 text-gray-300 hover:border-emerald-400'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="text-emerald-400">
                    {getAssetIcon(token.asset_type)}
                  </div>
                  <div>
                    <div className="font-medium">{token.symbol}</div>
                    <div className="text-sm opacity-80">{token.asset_name}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="font-medium">
                    {rwaRates[token.token_id]?.rate_wepo_per_token?.toFixed(6) || 'N/A'} WEPO
                  </div>
                  <div className="text-xs opacity-80">per token</div>
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {selectedToken && (
        <>
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
              Buy {selectedToken.symbol}
            </button>
            <button
              onClick={() => setSwapType('sell')}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                swapType === 'sell' 
                  ? 'bg-red-600 text-white' 
                  : 'text-gray-300 hover:text-white'
              }`}
            >
              Sell {selectedToken.symbol}
            </button>
          </div>

          <div className="space-y-4">
            {/* Token Amount */}
            <div>
              <label className="block text-sm font-medium text-purple-200 mb-2">
                {swapType === 'buy' ? `${selectedToken.symbol} to Buy` : `${selectedToken.symbol} to Sell`}
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={tokenAmount}
                  onChange={(e) => {
                    setTokenAmount(e.target.value);
                    const rate = rwaRates[selectedToken.token_id]?.rate_wepo_per_token || 1;
                    setWepoAmount((parseFloat(e.target.value) * rate || 0).toFixed(8));
                  }}
                  className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-20"
                  placeholder="0.00000000"
                  step="0.00000001"
                  min="0"
                />
                <div className="absolute right-3 top-3 text-gray-400 font-medium">
                  {selectedToken.symbol}
                </div>
              </div>
            </div>

            {/* WEPO Amount */}
            <div>
              <label className="block text-sm font-medium text-purple-200 mb-2">
                WEPO Amount
              </label>
              <div className="relative">
                <input
                  type="number"
                  value={wepoAmount}
                  onChange={(e) => setWepoAmount(e.target.value)}
                  className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-20"
                  placeholder="0.000000"
                  step="0.000001"
                  min="0"
                />
                <div className="absolute right-3 top-3 text-gray-400 font-medium">WEPO</div>
              </div>
            </div>

            {/* Trade Button */}
            <button
              onClick={handleRwaTrade}
              disabled={isLoading || !tokenAmount || !wepoAmount}
              className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              <Package size={20} />
              {isLoading ? 'Processing Trade...' : `${swapType === 'buy' ? 'Buy' : 'Sell'} ${selectedToken.symbol}`}
            </button>
          </div>
        </>
      )}
    </div>
  );

  const renderLiquidityInterface = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-600 to-indigo-600 rounded-xl p-6 text-white">
        <div className="flex items-center gap-3 mb-2">
          <Coins className="h-6 w-6" />
          <h3 className="text-xl font-bold">Add Liquidity</h3>
        </div>
        <p className="text-sm text-purple-100">
          {poolStats?.pool_exists 
            ? 'Add liquidity to earn fees from trades'
            : 'Create the market by providing initial liquidity'
          }
        </p>
      </div>

      {/* Pool Statistics */}
      {poolStats?.pool_exists && (
        <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
          <h4 className="text-lg font-semibold text-white mb-3">Pool Statistics</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-400">BTC Reserve:</span>
              <div className="text-white font-medium">{poolStats.btc_reserve?.toFixed(6)} BTC</div>
            </div>
            <div>
              <span className="text-gray-400">WEPO Reserve:</span>
              <div className="text-white font-medium">{poolStats.wepo_reserve?.toFixed(2)} WEPO</div>
            </div>
            <div>
              <span className="text-gray-400">Current Price:</span>
              <div className="text-white font-medium">{poolStats.current_price?.toFixed(6)} WEPO/BTC</div>
            </div>
            <div>
              <span className="text-gray-400">Total LPs:</span>
              <div className="text-white font-medium">{poolStats.total_lp_count}</div>
            </div>
          </div>
        </div>
      )}

      {/* Liquidity Form */}
      <div className="space-y-4">
        {/* BTC Amount */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            BTC Amount
          </label>
          <div className="relative">
            <input
              type="number"
              value={liquidityBtcAmount}
              onChange={(e) => {
                setLiquidityBtcAmount(e.target.value);
                // Auto-calculate WEPO amount if pool exists
                if (poolStats?.pool_exists && poolStats.current_price && e.target.value) {
                  setLiquidityWepoAmount((parseFloat(e.target.value) * poolStats.current_price).toFixed(6));
                }
              }}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-16"
              placeholder="0.00000000"
              step="0.00000001"
              min="0"
            />
            <div className="absolute right-3 top-3 text-gray-400 font-medium">BTC</div>
          </div>
        </div>

        {/* WEPO Amount */}
        <div>
          <label className="block text-sm font-medium text-purple-200 mb-2">
            WEPO Amount
          </label>
          <div className="relative">
            <input
              type="number"
              value={liquidityWepoAmount}
              onChange={(e) => setLiquidityWepoAmount(e.target.value)}
              className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 pr-20"
              placeholder="0.000000"
              step="0.000001"
              min="0"
            />
            <div className="absolute right-3 top-3 text-gray-400 font-medium">WEPO</div>
          </div>
        </div>

        {/* Pool Creation Notice */}
        {!poolStats?.pool_exists && (
          <div className="bg-yellow-900/30 rounded-lg p-4 border border-yellow-500/30">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="h-4 w-4 text-yellow-400" />
              <span className="text-sm font-medium text-yellow-200">Create Market</span>
            </div>
            <p className="text-sm text-gray-300">
              No liquidity pool exists yet. You will create the market and set the initial BTC/WEPO price ratio.
            </p>
          </div>
        )}

        {/* Add Liquidity Button */}
        <button
          onClick={handleAddLiquidity}
          disabled={isLoading || !liquidityBtcAmount || !liquidityWepoAmount}
          className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-3 px-6 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          <Coins size={20} />
          {isLoading ? 'Processing...' : 
           poolStats?.pool_exists ? 'Add Liquidity' : 'Create Market'
          }
        </button>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={onBack}
          className="text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={24} />
        </button>
        <div className="flex items-center gap-2">
          <ArrowRightLeft className="h-6 w-6 text-blue-400" />
          <h2 className="text-xl font-semibold text-white">WEPO DEX</h2>
        </div>
      </div>

      {/* DEX Type Toggle */}
      <div className="flex bg-gray-700 rounded-lg p-1">
        <button
          onClick={() => setActiveTab('btc')}
          className={`flex-1 py-3 px-4 rounded-md text-sm font-medium transition-colors flex items-center justify-center gap-2 ${
            activeTab === 'btc' 
              ? 'bg-blue-600 text-white' 
              : 'text-gray-300 hover:text-white'
          }`}
        >
          <Bitcoin className="h-4 w-4" />
          BTC DEX
        </button>
        <button
          onClick={() => setActiveTab('rwa')}
          className={`flex-1 py-3 px-4 rounded-md text-sm font-medium transition-colors flex items-center justify-center gap-2 ${
            activeTab === 'rwa' 
              ? 'bg-emerald-600 text-white' 
              : 'text-gray-300 hover:text-white'
          }`}
        >
          <Package className="h-4 w-4" />
          RWA DEX
        </button>
        <button
          onClick={() => setActiveTab('liquidity')}
          className={`flex-1 py-3 px-4 rounded-md text-sm font-medium transition-colors flex items-center justify-center gap-2 ${
            activeTab === 'liquidity' 
              ? 'bg-purple-600 text-white' 
              : 'text-gray-300 hover:text-white'
          }`}
        >
          <Coins className="h-4 w-4" />
          Liquidity
        </button>
      </div>

      {/* Content */}
      {activeTab === 'btc' ? renderBTCDEX() : 
       activeTab === 'rwa' ? renderRWADEX() : 
       renderLiquidityInterface()}

      {/* Error/Success Messages */}
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
          {activeTab === 'btc' 
            ? 'This is a trustless atomic swap. Make sure you have sufficient BTC in your external wallet.'
            : 'RWA tokens represent real world assets. Verify asset details before trading.'}
        </p>
      </div>
    </div>
  );
};

export default UnifiedExchange;