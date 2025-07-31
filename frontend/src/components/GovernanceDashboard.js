import React, { useState, useEffect } from 'react';

const GovernanceDashboard = () => {
  const [governanceStatus, setGovernanceStatus] = useState(null);
  const [halvingSchedule, setHalvingSchedule] = useState(null);
  const [protectionMechanisms, setProtectionMechanisms] = useState(null);
  const [activeProposals, setActiveProposals] = useState([]);
  const [timeLocked, setTimeLocked] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  useEffect(() => {
    fetchGovernanceData();
    // Refresh every 30 seconds
    const interval = setInterval(fetchGovernanceData, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchGovernanceData = async () => {
    try {
      setLoading(true);
      
      // Fetch all governance data in parallel
      const [statusRes, scheduleRes, protectionRes, proposalsRes, timeLockRes] = await Promise.all([
        fetch(`${backendUrl}/api/governance/halving-cycle/status`),
        fetch(`${backendUrl}/api/governance/halving-cycle/schedule`),
        fetch(`${backendUrl}/api/governance/halving-cycle/protection-status`),
        fetch(`${backendUrl}/api/governance/proposals/active`),
        fetch(`${backendUrl}/api/governance/halving-cycle/time-locked-proposals`)
      ]);

      if (statusRes.ok) {
        const statusData = await statusRes.json();
        setGovernanceStatus(statusData.governance_window_status);
      }

      if (scheduleRes.ok) {
        const scheduleData = await scheduleRes.json();
        setHalvingSchedule(scheduleData);
      }

      if (protectionRes.ok) {
        const protectionData = await protectionRes.json();
        setProtectionMechanisms(protectionData.protection_mechanisms);
      }

      if (proposalsRes.ok) {
        const proposalsData = await proposalsRes.json();
        setActiveProposals(proposalsData.active_proposals || []);
      }

      if (timeLockRes.ok) {
        const timeLockData = await timeLockRes.json();
        setTimeLocked(Object.values(timeLockData.time_locked_proposals || {}));
      }

      setError(null);
    } catch (err) {
      console.error('Error fetching governance data:', err);
      setError('Failed to load governance data');
    } finally {
      setLoading(false);
    }
  };

  if (loading && !governanceStatus) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error && !governanceStatus) {
    return (
      <div className="min-h-screen bg-gray-900 text-white p-8">
        <div className="max-w-6xl mx-auto">
          <div className="bg-red-900 border border-red-700 rounded-lg p-6">
            <h2 className="text-xl font-bold text-red-300 mb-2">🚨 Error Loading Governance</h2>
            <p className="text-red-200">{error}</p>
            <button 
              onClick={fetchGovernanceData}
              className="mt-4 bg-red-600 hover:bg-red-700 px-4 py-2 rounded transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-center mb-4">
            🏛️ WEPO Halving-Cycle Governance
          </h1>
          <p className="text-center text-gray-300 max-w-3xl mx-auto">
            Democratic network governance tied to PoW halving events. Community-driven decisions with enhanced protection mechanisms.
          </p>
        </div>

        {/* Governance Window Status */}
        <GovernanceWindowStatus 
          status={governanceStatus} 
          onRefresh={fetchGovernanceData}
        />

        {/* Current Phase & Halving Schedule */}
        <HalvingScheduleDisplay 
          schedule={halvingSchedule}
          currentStatus={governanceStatus}
        />

        {/* Protection Mechanisms */}
        <ProtectionMechanismsDisplay 
          mechanisms={protectionMechanisms}
        />

        {/* Active Proposals */}
        <ActiveProposalsSection 
          proposals={activeProposals}
          onRefresh={fetchGovernanceData}
        />

        {/* Time-Locked Proposals */}
        <TimeLocked proposals={timeLocked} />

        {/* Proposal Creation */}
        <ProposalCreationSection 
          governanceStatus={governanceStatus}
          onProposalCreated={fetchGovernanceData}
        />
      </div>
    </div>
  );
};

// Governance Window Status Component
const GovernanceWindowStatus = ({ status, onRefresh }) => {
  if (!status) return null;

  const isOpen = status.window_open;
  const statusColor = isOpen ? 'bg-green-900 border-green-700' : 'bg-red-900 border-red-700';
  const statusIcon = isOpen ? '🟢' : '🔴';
  const statusText = isOpen ? 'OPEN' : 'CLOSED';

  return (
    <div className={`${statusColor} border rounded-lg p-6 mb-8`}>
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">
          {statusIcon} Governance Window: {statusText}
        </h2>
        <button 
          onClick={onRefresh}
          className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded transition-colors"
        >
          🔄 Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <h3 className="text-lg font-semibold mb-2">Current Phase</h3>
          <p className="text-xl">{status.current_phase?.name}</p>
          <p className="text-gray-300 text-sm">
            Block Height: {status.current_height?.toLocaleString()}
          </p>
          <p className="text-gray-300 text-sm">
            PoW Reward: {status.current_phase?.pow_reward} WEPO
          </p>
        </div>

        <div>
          <h3 className="text-lg font-semibold mb-2">
            {isOpen ? 'Time Remaining' : 'Next Window'}
          </h3>
          {isOpen ? (
            <div>
              <p className="text-xl text-green-400">
                {status.governance_window?.days_remaining?.toFixed(1)} days remaining
              </p>
              <p className="text-gray-300 text-sm">
                Window ends at block {status.governance_window?.end_height?.toLocaleString()}
              </p>
            </div>
          ) : (
            <div>
              {status.next_governance_window?.days_until_next ? (
                <>
                  <p className="text-xl text-orange-400">
                    {status.next_governance_window.days_until_next.toFixed(1)} days until next
                  </p>
                  <p className="text-gray-300 text-sm">
                    Next: {status.next_governance_window.next_phase}
                  </p>
                </>
              ) : (
                <p className="text-gray-400">No upcoming windows scheduled</p>
              )}
            </div>
          )}
        </div>
      </div>

      {isOpen && (
        <div className="mt-4 p-4 bg-green-800 rounded">
          <p className="text-green-200">
            ✅ Governance window is active! You can create and vote on proposals.
          </p>
        </div>
      )}
    </div>
  );
};

// Halving Schedule Display Component
const HalvingScheduleDisplay = ({ schedule, currentStatus }) => {
  const [showFullSchedule, setShowFullSchedule] = useState(false);

  if (!schedule) return null;

  const currentPhase = schedule.halving_schedule?.find(phase => phase.is_current);
  const upcomingPhases = schedule.halving_schedule?.filter(phase => 
    phase.start_height > (currentStatus?.current_height || 0)
  ).slice(0, 3);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-8">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">📅 Halving Schedule & Governance Windows</h2>
        <button 
          onClick={() => setShowFullSchedule(!showFullSchedule)}
          className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded transition-colors"
        >
          {showFullSchedule ? 'Hide Full Schedule' : 'Show Full Schedule'}
        </button>
      </div>

      {/* Current Phase */}
      {currentPhase && (
        <div className="mb-6 p-4 bg-blue-900 border border-blue-700 rounded">
          <h3 className="text-lg font-semibold text-blue-200 mb-2">Current Phase</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <p className="text-blue-300 font-medium">{currentPhase.phase_name}</p>
              <p className="text-gray-300 text-sm">{currentPhase.duration_months} months</p>
            </div>
            <div>
              <p className="text-blue-300">PoW Reward: {currentPhase.pow_reward} WEPO</p>
              <p className="text-gray-300 text-sm">
                Blocks: {currentPhase.start_height?.toLocaleString()} - {
                  currentPhase.end_height === Infinity ? '∞' : currentPhase.end_height?.toLocaleString()
                }
              </p>
            </div>
            <div>
              <p className="text-blue-300">
                Governance: {currentPhase.governance_duration_days > 0 ? 
                  `${currentPhase.governance_duration_days} days` : 'None'}
              </p>
              {currentPhase.governance_window_start > 0 && (
                <p className="text-gray-300 text-sm">
                  Window: {currentPhase.governance_window_start?.toLocaleString()} - {
                    currentPhase.governance_window_end?.toLocaleString()
                  }
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Upcoming Phases */}
      {upcomingPhases && upcomingPhases.length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-semibold mb-3">Upcoming Governance Windows</h3>
          <div className="space-y-3">
            {upcomingPhases.map((phase, index) => (
              <div key={index} className="p-3 bg-gray-700 rounded">
                <div className="flex justify-between items-center">
                  <div>
                    <p className="font-medium">{phase.phase_name}</p>
                    <p className="text-gray-300 text-sm">
                      {phase.duration_months} months • {phase.pow_reward} WEPO reward
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-orange-400">
                      {phase.governance_duration_days > 0 ? 
                        `${phase.governance_duration_days} day window` : 'No governance'}
                    </p>
                    <p className="text-gray-400 text-sm">
                      Block {phase.start_height?.toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Full Schedule */}
      {showFullSchedule && schedule.halving_schedule && (
        <div className="mt-6">
          <h3 className="text-lg font-semibold mb-3">Complete Halving Schedule</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-700">
                  <th className="text-left p-3">Phase</th>
                  <th className="text-left p-3">Duration</th>
                  <th className="text-left p-3">PoW Reward</th>
                  <th className="text-left p-3">Governance Window</th>
                  <th className="text-left p-3">Block Range</th>
                </tr>
              </thead>
              <tbody>
                {schedule.halving_schedule.map((phase, index) => (
                  <tr key={index} className={phase.is_current ? 'bg-blue-900' : 'hover:bg-gray-700'}>
                    <td className="p-3">{phase.phase_name}</td>
                    <td className="p-3">{phase.duration_months} months</td>
                    <td className="p-3">{phase.pow_reward} WEPO</td>
                    <td className="p-3">
                      {phase.governance_duration_days > 0 ? 
                        `${phase.governance_duration_days} days` : 'None'}
                    </td>
                    <td className="p-3 text-xs">
                      {phase.start_height?.toLocaleString()} - {
                        phase.end_height === Infinity ? '∞' : phase.end_height?.toLocaleString()
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

// Protection Mechanisms Display Component
const ProtectionMechanismsDisplay = ({ mechanisms }) => {
  if (!mechanisms) return null;

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-8">
      <h2 className="text-2xl font-bold mb-4">🛡️ Protection Mechanisms</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Community Veto */}
        <div className="p-4 bg-purple-900 border border-purple-700 rounded">
          <h3 className="text-lg font-semibold text-purple-200 mb-2">
            🗳️ Community Veto
          </h3>
          <p className="text-2xl font-bold text-purple-300">
            {mechanisms.community_veto?.threshold}
          </p>
          <p className="text-gray-300 text-sm">
            {mechanisms.community_veto?.description}
          </p>
          <p className="text-purple-400 text-sm mt-2">
            Active Vetos: {mechanisms.community_veto?.active_vetos || 0}
          </p>
        </div>

        {/* Masternode Voting */}
        <div className="p-4 bg-green-900 border border-green-700 rounded">
          <h3 className="text-lg font-semibold text-green-200 mb-2">
            ⚖️ Democratic Voting
          </h3>
          <p className="text-2xl font-bold text-green-300">
            1:1 Ratio
          </p>
          <p className="text-gray-300 text-sm">
            {mechanisms.masternode_voting?.description}
          </p>
          <p className="text-green-400 text-sm mt-2">
            Prevents: {mechanisms.masternode_voting?.prevents}
          </p>
        </div>

        {/* Time-locked Execution */}
        <div className="p-4 bg-orange-900 border border-orange-700 rounded">
          <h3 className="text-lg font-semibold text-orange-200 mb-2">
            ⏰ Time-locked Execution
          </h3>
          <div className="text-orange-300">
            <p className="text-sm">Low Risk: {mechanisms.time_locked_execution?.delays?.low_risk}d</p>
            <p className="text-sm">Medium: {mechanisms.time_locked_execution?.delays?.medium_risk}d</p>
            <p className="text-sm">High Risk: {mechanisms.time_locked_execution?.delays?.high_risk}d</p>
          </div>
          <p className="text-orange-400 text-sm mt-2">
            Scheduled: {mechanisms.time_locked_execution?.scheduled_executions || 0}
          </p>
        </div>

        {/* Immutable Protection */}
        <div className="p-4 bg-red-900 border border-red-700 rounded">
          <h3 className="text-lg font-semibold text-red-200 mb-2">
            🔒 Immutable Core
          </h3>
          <p className="text-2xl font-bold text-red-300">
            {mechanisms.immutable_protection?.protected_parameters} Parameters
          </p>
          <p className="text-gray-300 text-sm">
            {mechanisms.immutable_protection?.description}
          </p>
          <p className="text-red-400 text-sm mt-2">
            Prevents: {mechanisms.immutable_protection?.prevents}
          </p>
        </div>

        {/* Governance Windows */}
        <div className="p-4 bg-blue-900 border border-blue-700 rounded">
          <h3 className="text-lg font-semibold text-blue-200 mb-2">
            🪟 Governance Windows
          </h3>
          <p className="text-xl font-bold text-blue-300">
            Halving-Cycle
          </p>
          <p className="text-gray-300 text-sm">
            {mechanisms.governance_windows?.description}
          </p>
          <p className="text-blue-400 text-sm mt-2">
            Ensures: {mechanisms.governance_windows?.ensures}
          </p>
        </div>
      </div>
    </div>
  );
};

// Active Proposals Section
const ActiveProposalsSection = ({ proposals, onRefresh }) => {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-8">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">📋 Active Proposals</h2>
        <span className="bg-blue-600 text-white px-3 py-1 rounded">
          {proposals.length} Active
        </span>
      </div>

      {proposals.length === 0 ? (
        <div className="text-center py-8 text-gray-400">
          <p>No active proposals</p>
          <p className="text-sm mt-2">Proposals can only be created during governance windows</p>
        </div>
      ) : (
        <div className="space-y-4">
          {proposals.map((proposal, index) => (
            <ProposalCard key={index} proposal={proposal} onUpdate={onRefresh} />
          ))}
        </div>
      )}
    </div>
  );
};

// Individual Proposal Card
const ProposalCard = ({ proposal, onUpdate }) => {
  const [isVoting, setIsVoting] = useState(false);

  const handleVote = async (proposalId, choice) => {
    // This would implement the voting logic
    console.log('Voting:', proposalId, choice);
  };

  const handleVeto = async (proposalId) => {
    // This would implement the veto logic
    console.log('Vetoing:', proposalId);
  };

  return (
    <div className="p-4 bg-gray-700 border border-gray-600 rounded">
      <div className="flex justify-between items-start mb-3">
        <div>
          <h3 className="text-lg font-semibold">{proposal.proposal?.title}</h3>
          <p className="text-gray-300 text-sm">{proposal.proposal?.description}</p>
        </div>
        <span className={`px-2 py-1 rounded text-xs ${
          proposal.voting_status === 'active' ? 'bg-green-600' : 'bg-gray-600'
        }`}>
          {proposal.voting_status}
        </span>
      </div>

      <div className="grid grid-cols-3 gap-4 mb-4">
        <div>
          <p className="text-sm text-gray-400">Participation</p>
          <p className="text-lg">
            {(proposal.current_results?.participation_rate * 100)?.toFixed(1)}%
          </p>
        </div>
        <div>
          <p className="text-sm text-gray-400">Approval</p>
          <p className="text-lg">
            {(proposal.current_results?.approval_rate * 100)?.toFixed(1)}%
          </p>
        </div>
        <div>
          <p className="text-sm text-gray-400">Time Left</p>
          <p className="text-lg">
            {Math.max(0, Math.floor(proposal.time_remaining / 3600))}h
          </p>
        </div>
      </div>

      <div className="flex space-x-2">
        <button 
          onClick={() => handleVote(proposal.proposal?.proposal_id, 'yes')}
          className="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-sm transition-colors"
        >
          Vote Yes
        </button>
        <button 
          onClick={() => handleVote(proposal.proposal?.proposal_id, 'no')}
          className="bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-sm transition-colors"
        >
          Vote No
        </button>
        <button 
          onClick={() => handleVeto(proposal.proposal?.proposal_id)}
          className="bg-purple-600 hover:bg-purple-700 px-3 py-1 rounded text-sm transition-colors"
        >
          Community Veto
        </button>
      </div>
    </div>
  );
};

// Time-Locked Proposals
const TimeLocked = ({ proposals }) => {
  if (!proposals || proposals.length === 0) return null;

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-8">
      <h2 className="text-2xl font-bold mb-4">⏰ Time-Locked Proposals</h2>
      
      <div className="space-y-4">
        {proposals.map((proposal, index) => (
          <div key={index} className="p-4 bg-orange-900 border border-orange-700 rounded">
            <div className="flex justify-between items-center">
              <div>
                <p className="font-semibold">Proposal: {proposal.proposal_id}</p>
                <p className="text-sm text-gray-300">
                  Risk Level: {proposal.risk_level} • Delay: {proposal.delay_days} days
                </p>
              </div>
              <div className="text-right">
                <p className="text-orange-300">
                  {Math.floor((proposal.execution_time * 1000 - Date.now()) / (1000 * 60 * 60 * 24))} days remaining
                </p>
                <p className="text-xs text-gray-400">
                  Block: {proposal.execution_height?.toLocaleString()}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Proposal Creation Section
const ProposalCreationSection = ({ governanceStatus, onProposalCreated }) => {
  const canCreateProposal = governanceStatus?.window_open;
  
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
      <h2 className="text-2xl font-bold mb-4">✍️ Create Proposal</h2>
      
      {canCreateProposal ? (
        <ProposalCreationForm onSuccess={onProposalCreated} />
      ) : (
        <div className="text-center py-8">
          <div className="text-6xl mb-4">🔒</div>
          <p className="text-xl text-gray-300 mb-2">Governance Window Closed</p>
          <p className="text-gray-400">
            Proposals can only be created during governance windows tied to halving events.
          </p>
          {governanceStatus?.next_governance_window?.days_until_next && (
            <p className="text-orange-400 mt-2">
              Next window opens in {governanceStatus.next_governance_window.days_until_next.toFixed(1)} days
            </p>
          )}
        </div>
      )}
    </div>
  );
};

// Proposal Creation Form
const ProposalCreationForm = ({ onSuccess }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    proposal_type: 'network_parameter',
    target_parameter: '',
    proposed_value: '',
    current_value: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      const response = await fetch(`${backendUrl}/api/governance/halving-cycle/proposals/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...formData,
          proposer_address: 'wepo1test' + Math.random().toString(36).substr(2, 33) // Mock address
        }),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setFormData({
            title: '',
            description: '',
            proposal_type: 'network_parameter',
            target_parameter: '',
            proposed_value: '',
            current_value: ''
          });
          onSuccess();
        } else {
          setError(data.message || 'Failed to create proposal');
        }
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Failed to create proposal');
      }
    } catch (err) {
      setError('Network error: Failed to create proposal');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Title</label>
          <input
            type="text"
            value={formData.title}
            onChange={(e) => setFormData({...formData, title: e.target.value})}
            className="w-full p-3 bg-gray-700 border border-gray-600 rounded focus:border-blue-500"
            placeholder="Proposal title"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Type</label>
          <select
            value={formData.proposal_type}
            onChange={(e) => setFormData({...formData, proposal_type: e.target.value})}
            className="w-full p-3 bg-gray-700 border border-gray-600 rounded focus:border-blue-500"
          >
            <option value="network_parameter">Network Parameter</option>
            <option value="collateral_override">Collateral Override</option>
            <option value="economic_policy">Economic Policy</option>
            <option value="emergency_action">Emergency Action</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium mb-2">Description</label>
        <textarea
          value={formData.description}
          onChange={(e) => setFormData({...formData, description: e.target.value})}
          className="w-full p-3 bg-gray-700 border border-gray-600 rounded focus:border-blue-500"
          rows="3"
          placeholder="Detailed description of the proposal"
          required
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium mb-2">Target Parameter</label>
          <input
            type="text"
            value={formData.target_parameter}
            onChange={(e) => setFormData({...formData, target_parameter: e.target.value})}
            className="w-full p-3 bg-gray-700 border border-gray-600 rounded focus:border-blue-500"
            placeholder="e.g., block_size_limit"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Current Value</label>
          <input
            type="text"
            value={formData.current_value}
            onChange={(e) => setFormData({...formData, current_value: e.target.value})}
            className="w-full p-3 bg-gray-700 border border-gray-600 rounded focus:border-blue-500"
            placeholder="Current value"
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium mb-2">Proposed Value</label>
          <input
            type="text"
            value={formData.proposed_value}
            onChange={(e) => setFormData({...formData, proposed_value: e.target.value})}
            className="w-full p-3 bg-gray-700 border border-gray-600 rounded focus:border-blue-500"
            placeholder="New proposed value"
            required
          />
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-900 border border-red-700 rounded text-red-200">
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={isSubmitting}
        className={`w-full py-3 px-6 rounded font-semibold transition-colors ${
          isSubmitting 
            ? 'bg-gray-600 cursor-not-allowed' 
            : 'bg-blue-600 hover:bg-blue-700'
        }`}
      >
        {isSubmitting ? 'Creating Proposal...' : 'Create Proposal'}
      </button>
    </form>
  );
};

export default GovernanceDashboard;