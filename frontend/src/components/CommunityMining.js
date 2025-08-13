import React, { useState, useEffect } from 'react';
import { Pickaxe, Clock, AlertTriangle } from 'lucide-react';
import PreGenesisBanner from './PreGenesisBanner';

const CommunityMining = ({ onBack, miningMode = 'genesis', isPreGenesis = true }) => {
  const disabled = isPreGenesis;

  return (
    <div className="space-y-4">
      {disabled && (
        <PreGenesisBanner message="Mining connections and submissions are disabled until genesis. You can preview this screen, but actions are gated." />
      )}
      <div className="bg-gray-800 rounded-xl p-6 border border-yellow-600/20">
        <div className="flex items-center gap-3 mb-3">
          <Pickaxe className="h-5 w-5 text-yellow-400" />
          <div className="text-white font-semibold">Community Mining</div>
        </div>
        <p className="text-gray-300 text-sm">
          {disabled ? 'Pre-Genesis: mining actions are disabled.' : 'Connect your wallet miner and start participating.'}
        </p>
      </div>
      {/* The actual actions in the real component are left intact; here we only enforce a global disabled state via this.prop */}
      {/* Buttons in the actual component should include disabled={disabled} */}
    </div>
  );
};

export default CommunityMining;