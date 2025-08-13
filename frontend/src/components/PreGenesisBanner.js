import React from 'react';
import { AlertTriangle } from 'lucide-react';

const PreGenesisBanner = ({ compact = false, message }) => {
  return (
    <div className={`w-full ${compact ? 'p-3' : 'p-4'} mb-4 rounded-lg border border-yellow-500/30 bg-yellow-900/30`}>
      <div className="flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-yellow-300 mt-0.5" />
        <div>
          <div className="text-yellow-200 font-semibold">
            Pre-Genesis Network
          </div>
          <div className="text-yellow-100/90 text-sm">
            {message || 'The WEPO network has not launched yet. All state-changing actions are disabled until genesis.'}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PreGenesisBanner;