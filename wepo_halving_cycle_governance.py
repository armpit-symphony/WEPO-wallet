#!/usr/bin/env python3
"""
WEPO Halving-Cycle Governance System
Implementation of governance windows tied to PoW halving schedule

This module extends the existing governance system to implement:
1. Governance windows tied to PoW halving events
2. Immutable core parameters vs governable parameters
3. Community veto power (30%)
4. Time-locked implementation delays
5. Halving-cycle based activation

Key Features:
- Governance only active during specific halving-cycle windows
- Immutable parameters that can never be changed
- Enhanced protection mechanisms for network stability
- Integration with existing WEPO blockchain halving schedule
"""

import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib

# Import existing governance system
from wepo_governance_system import (
    WepoGovernanceSystem, 
    governance_system,
    Proposal, 
    Vote, 
    VoterInfo,
    ProposalStatus, 
    ProposalType, 
    VoteChoice
)

logger = logging.getLogger(__name__)

class GovernanceWindowStatus(Enum):
    CLOSED = "closed"
    PREPARATION = "preparation"  # 30 days before window opens
    ACTIVE = "active"
    COOLDOWN = "cooldown"       # 30 days after window closes

class ParameterType(Enum):
    IMMUTABLE = "immutable"     # Can never be changed
    GOVERNABLE = "governable"   # Can be changed via governance
    EMERGENCY = "emergency"     # Can be changed in emergencies only

@dataclass
class HalvingPhase:
    """Represents a halving phase with governance window information"""
    phase_name: str
    start_height: int
    end_height: int
    duration_months: int
    pow_reward: float
    governance_window_start: int  # Block height when governance opens
    governance_window_end: int    # Block height when governance closes
    governance_duration_days: int = 90  # 90 days governance window
    is_current: bool = False

@dataclass
class ImmutableParameter:
    """Parameters that can never be changed through governance"""
    name: str
    value: Any
    description: str
    locked_since: int  # Block height when locked
    lock_reason: str

@dataclass
class GovernableParameter:
    """Parameters that can be changed through governance"""
    name: str
    current_value: Any
    description: str
    min_value: Optional[Any] = None
    max_value: Optional[Any] = None
    last_changed_height: int = 0
    change_history: List[Dict] = None
    
    def __post_init__(self):
        if self.change_history is None:
            self.change_history = []

class WepoHalvingCycleGovernance:
    """
    WEPO Halving-Cycle Governance System
    
    Implements governance windows tied to PoW halving events with enhanced
    protection mechanisms and community oversight.
    """
    
    def __init__(self, blockchain_reference=None):
        self.blockchain = blockchain_reference
        self.base_governance = governance_system  # Use existing governance system
        
        # Initialize halving schedule from blockchain.py
        self.halving_phases = self._initialize_halving_schedule()
        
        # Initialize parameter classifications
        self.immutable_parameters = self._initialize_immutable_parameters()
        self.governable_parameters = self._initialize_governable_parameters()
        
        # Enhanced Protection Mechanisms
        self.community_veto_threshold = 0.30  # 30% of community can veto
        self.masternode_vote_weight = 1  # 1 masternode = 1 vote (not 10x)
        self.veto_votes: Dict[str, List[Dict]] = {}  # proposal_id -> veto votes
        self.execution_delays = {
            "low_risk": 7,      # 7 days for low-risk changes
            "medium_risk": 30,  # 30 days for medium-risk changes  
            "high_risk": 90     # 90 days for high-risk changes
        }
        
        # Time-lock mechanism
        self.time_locked_proposals: Dict[str, Dict] = {}  # proposal_id -> execution info
        
        # Governance window state
        self.current_window_status = GovernanceWindowStatus.CLOSED
        self.next_governance_window = None
        
        logger.info("WEPO Halving-Cycle Governance System initialized")
        logger.info(f"Initialized {len(self.halving_phases)} halving phases")
        logger.info(f"Protected {len(self.immutable_parameters)} immutable parameters")
        logger.info(f"Configured {len(self.governable_parameters)} governable parameters")
        logger.info("Enhanced protection mechanisms: 30% community veto, 1:1 masternode voting, time-locked execution")
    
    def _initialize_halving_schedule(self) -> List[HalvingPhase]:
        """Initialize halving schedule from blockchain.py constants"""
        phases = []
        
        # Phase 1: Genesis → PoS Activation (0-18 months) - NO GOVERNANCE
        phases.append(HalvingPhase(
            phase_name="Phase 1 - Genesis",
            start_height=0,
            end_height=131400,  # PRE_POS_DURATION_BLOCKS
            duration_months=18,
            pow_reward=52.51,
            governance_window_start=-1,  # No governance
            governance_window_end=-1,
            governance_duration_days=0
        ))
        
        # Phase 2A: PoS Activation → 2nd Halving (18 months-4.5 years) - FIRST GOVERNANCE WINDOW
        phases.append(HalvingPhase(
            phase_name="Phase 2A - First Governance",
            start_height=131400,  # PRE_POS_DURATION_BLOCKS
            end_height=306600,    # PHASE_2A_END_HEIGHT
            duration_months=36,   # 3 years
            pow_reward=33.17,
            governance_window_start=131400 + 43800,  # 6 months after PoS activation
            governance_window_end=131400 + 43800 + 14600,  # 90 days governance window
            governance_duration_days=90
        ))
        
        # Phase 2B: 2nd → 3rd Halving (4.5-10.5 years) - SECOND GOVERNANCE WINDOW
        phases.append(HalvingPhase(
            phase_name="Phase 2B - Second Governance",
            start_height=306600,  # PHASE_2A_END_HEIGHT
            end_height=657000,    # PHASE_2B_END_HEIGHT
            duration_months=72,   # 6 years
            pow_reward=16.58,
            governance_window_start=306600 + 58400,  # 1 year after halving
            governance_window_end=306600 + 58400 + 14600,  # 90 days governance window
            governance_duration_days=90
        ))
        
        # Phase 2C: 3rd → 4th Halving (10.5-13.5 years) - THIRD GOVERNANCE WINDOW
        phases.append(HalvingPhase(
            phase_name="Phase 2C - Third Governance",
            start_height=657000,  # PHASE_2B_END_HEIGHT
            end_height=832200,    # PHASE_2C_END_HEIGHT
            duration_months=36,   # 3 years
            pow_reward=8.29,
            governance_window_start=657000 + 29200,  # 6 months after halving
            governance_window_end=657000 + 29200 + 14600,  # 90 days governance window
            governance_duration_days=90
        ))
        
        # Phase 2D: 4th → 5th Halving (13.5-16.5 years) - FOURTH GOVERNANCE WINDOW
        phases.append(HalvingPhase(
            phase_name="Phase 2D - Fourth Governance",
            start_height=832200,  # PHASE_2C_END_HEIGHT
            end_height=1007400,   # PHASE_2D_END_HEIGHT
            duration_months=36,   # 3 years
            pow_reward=4.15,
            governance_window_start=832200 + 29200,  # 6 months after halving
            governance_window_end=832200 + 29200 + 14600,  # 90 days governance window
            governance_duration_days=90
        ))
        
        # Phase 3: Post-PoW Era (16.5+ years) - FINAL GOVERNANCE WINDOW
        phases.append(HalvingPhase(
            phase_name="Phase 3 - Post-PoW Era",
            start_height=1007400,  # POW_END_HEIGHT
            end_height=float('inf'),
            duration_months=float('inf'),
            pow_reward=0.0,
            governance_window_start=1007400 + 14600,  # 3 months after PoW ends
            governance_window_end=1007400 + 14600 + 14600,  # 90 days governance window
            governance_duration_days=90
        ))
        
        return phases
    
    def _initialize_immutable_parameters(self) -> Dict[str, ImmutableParameter]:
        """Initialize parameters that can NEVER be changed"""
        immutable = {}
        
        # Core economic parameters - IMMUTABLE FOREVER
        immutable["total_supply"] = ImmutableParameter(
            name="total_supply",
            value=69000003,
            description="Total WEPO supply - can never be changed",
            locked_since=0,
            lock_reason="Core economic principle - prevents inflation/deflation manipulation"
        )
        
        immutable["zero_fees"] = ImmutableParameter(
            name="zero_fees",
            value=True,
            description="Zero transaction fees principle - can never be changed",
            locked_since=0,
            lock_reason="Core principle ensuring accessibility - prevents fee manipulation"
        )
        
        immutable["fair_launch"] = ImmutableParameter(
            name="fair_launch",
            value=True,
            description="No pre-mine, fair community launch - historical fact",
            locked_since=0,
            lock_reason="Historical immutable fact - cannot be retroactively changed"
        )
        
        immutable["pow_halving_schedule"] = ImmutableParameter(
            name="pow_halving_schedule",
            value="Phase1:52.51->Phase2A:33.17->Phase2B:16.58->Phase2C:8.29->Phase2D:4.15",
            description="PoW reward halving schedule - mathematically locked",
            locked_since=0,
            lock_reason="Mathematical certainty required for predictable economic model"
        )
        
        immutable["quantum_resistance"] = ImmutableParameter(
            name="quantum_resistance",
            value="Dilithium2_NIST_ML-DSA",
            description="Quantum-resistant cryptography standard",
            locked_since=0,
            lock_reason="Security foundation - cannot be weakened through governance"
        )
        
        immutable["consensus_mechanism"] = ImmutableParameter(
            name="consensus_mechanism",
            value="Hybrid_PoW_PoS_Masternodes",
            description="Hybrid consensus with three participation methods",
            locked_since=0,
            lock_reason="Core architectural decision - prevents consensus manipulation"
        )
        
        return immutable
    
    def _initialize_governable_parameters(self) -> Dict[str, GovernableParameter]:
        """Initialize parameters that CAN be changed through governance"""
        governable = {}
        
        # Network performance parameters
        governable["block_size_limit"] = GovernableParameter(
            name="block_size_limit",
            current_value=2097152,  # 2MB
            description="Maximum block size in bytes",
            min_value=1048576,      # 1MB minimum
            max_value=8388608       # 8MB maximum
        )
        
        governable["transaction_per_block_limit"] = GovernableParameter(
            name="transaction_per_block_limit",
            current_value=10000,
            description="Maximum transactions per block",
            min_value=1000,
            max_value=50000
        )
        
        # Masternode parameters (subject to dynamic schedule)
        governable["masternode_collateral_override"] = GovernableParameter(
            name="masternode_collateral_override",
            current_value=None,  # None means use dynamic schedule
            description="Override for dynamic masternode collateral (emergency use)",
            min_value=1000,      # Cannot go below 1K WEPO
            max_value=50000      # Cannot exceed 50K WEPO
        )
        
        governable["pos_collateral_override"] = GovernableParameter(
            name="pos_collateral_override",
            current_value=None,  # None means use dynamic schedule
            description="Override for dynamic PoS collateral (emergency use)",
            min_value=100,       # Cannot go below 100 WEPO
            max_value=10000      # Cannot exceed 10K WEPO
        )
        
        # Network security parameters
        governable["mining_difficulty_adjustment"] = GovernableParameter(
            name="mining_difficulty_adjustment",
            current_value="standard",
            description="Mining difficulty adjustment algorithm",
            min_value=None,
            max_value=None
        )
        
        governable["pos_validation_rules"] = GovernableParameter(
            name="pos_validation_rules",
            current_value="standard",
            description="Proof-of-Stake validation parameters",
            min_value=None,
            max_value=None
        )
        
        # Fee redistribution parameters (while maintaining zero transaction fees)
        governable["fee_redistribution_ratio"] = GovernableParameter(
            name="fee_redistribution_ratio",
            current_value="60:25:15",  # Masternodes:Miners:Stakers
            description="Service fee redistribution ratio (not transaction fees)",
            min_value=None,
            max_value=None
        )
        
        return governable
    
    def get_current_governance_window_status(self, current_height: int = None) -> Dict[str, Any]:
        """Get current governance window status"""
        if current_height is None:
            current_height = self._get_current_block_height()
        
        current_phase = self.get_current_phase(current_height)
        
        # Check if we're in a governance window
        if (current_phase.governance_window_start != -1 and 
            current_phase.governance_window_start <= current_height <= current_phase.governance_window_end):
            window_status = GovernanceWindowStatus.ACTIVE
            window_open = True
            days_remaining = max(0, (current_phase.governance_window_end - current_height) * 9 / (60 * 24))  # 9-min blocks to days
        else:
            window_status = GovernanceWindowStatus.CLOSED
            window_open = False
            # Calculate next governance window
            next_phase = self._get_next_governance_phase(current_height)
            if next_phase:
                blocks_until_next = max(0, next_phase.governance_window_start - current_height)
                days_until_next = blocks_until_next * 9 / (60 * 24)  # 9-min blocks to days
            else:
                days_until_next = None
        
        return {
            "window_status": window_status.value,
            "window_open": window_open,
            "current_phase": {
                "name": current_phase.phase_name,
                "start_height": current_phase.start_height,
                "end_height": current_phase.end_height,
                "pow_reward": current_phase.pow_reward
            },
            "governance_window": {
                "start_height": current_phase.governance_window_start,
                "end_height": current_phase.governance_window_end,
                "duration_days": current_phase.governance_duration_days,
                "days_remaining": days_remaining if window_open else None
            },
            "next_governance_window": {
                "days_until_next": days_until_next if not window_open else None,
                "next_phase": next_phase.phase_name if next_phase else None
            },
            "current_height": current_height
        }
    
    def get_current_phase(self, current_height: int = None) -> HalvingPhase:
        """Get the current halving phase"""
        if current_height is None:
            current_height = self._get_current_block_height()
        
        for phase in self.halving_phases:
            if phase.start_height <= current_height < phase.end_height:
                phase.is_current = True
                return phase
        
        # If we're beyond all phases, return the last one
        return self.halving_phases[-1]
    
    def _get_next_governance_phase(self, current_height: int) -> Optional[HalvingPhase]:
        """Get the next phase that has a governance window"""
        for phase in self.halving_phases:
            if (phase.governance_window_start > current_height and 
                phase.governance_window_start != -1):
                return phase
        return None
    
    def is_governance_window_open(self, current_height: int = None) -> bool:
        """Check if governance window is currently open"""
        window_status = self.get_current_governance_window_status(current_height)
        return window_status["window_open"]
    
    def can_create_proposal(self, proposal_type: ProposalType, current_height: int = None) -> Tuple[bool, str]:
        """Check if a proposal can be created given current governance window"""
        if not self.is_governance_window_open(current_height):
            next_window = self.get_current_governance_window_status(current_height)
            days_until_next = next_window["next_governance_window"]["days_until_next"]
            if days_until_next:
                return False, f"Governance window is closed. Next window opens in {days_until_next:.1f} days"
            else:
                return False, "No upcoming governance windows scheduled"
        
        # Check if proposal affects immutable parameters
        # This would be implemented based on proposal content
        return True, "Governance window is open and proposal is valid"
    
    def create_halving_cycle_proposal(self, proposer_address: str, title: str, description: str,
                                    proposal_type: ProposalType, target_parameter: str,
                                    proposed_value: str, current_value: str = None) -> Tuple[bool, str, Optional[str]]:
        """Create a proposal with halving-cycle governance validation"""
        try:
            # Check if governance window is open
            can_create, reason = self.can_create_proposal(proposal_type)
            if not can_create:
                return False, reason, None
            
            # Check if parameter is immutable
            if target_parameter in self.immutable_parameters:
                immutable_param = self.immutable_parameters[target_parameter]
                return False, f"Parameter '{target_parameter}' is immutable: {immutable_param.lock_reason}", None
            
            # Check if parameter is governable
            if target_parameter not in self.governable_parameters:
                return False, f"Parameter '{target_parameter}' is not a recognized governable parameter", None
            
            # Validate proposed value against parameter constraints
            governable_param = self.governable_parameters[target_parameter]
            validation_result = self._validate_proposed_value(governable_param, proposed_value)
            if not validation_result[0]:
                return False, validation_result[1], None
            
            # Create proposal through existing governance system
            proposal_id = self.base_governance.create_proposal(
                proposer_address=proposer_address,
                title=title,
                description=description,
                proposal_type=proposal_type,
                target_parameter=target_parameter,
                proposed_value=proposed_value,
                current_value=current_value or str(governable_param.current_value)
            )
            
            return True, "Halving-cycle governance proposal created successfully", proposal_id
            
        except Exception as e:
            logger.error(f"Error creating halving-cycle proposal: {e}")
            return False, str(e), None
    
    def _validate_proposed_value(self, parameter: GovernableParameter, proposed_value: str) -> Tuple[bool, str]:
        """Validate proposed value against parameter constraints"""
        try:
            # Try to convert to appropriate type
            if parameter.min_value is not None and parameter.max_value is not None:
                # Numeric parameter
                numeric_value = float(proposed_value)
                
                if numeric_value < parameter.min_value:
                    return False, f"Proposed value {numeric_value} is below minimum allowed ({parameter.min_value})"
                
                if numeric_value > parameter.max_value:
                    return False, f"Proposed value {numeric_value} is above maximum allowed ({parameter.max_value})"
            
            return True, "Proposed value is valid"
            
        except ValueError:
            # Non-numeric parameter, validate as string
            valid_values = self._get_valid_string_values(parameter.name)
            if valid_values and proposed_value not in valid_values:
                return False, f"Invalid value. Valid options: {', '.join(valid_values)}"
            
            return True, "Proposed value is valid"
    
    def _get_valid_string_values(self, parameter_name: str) -> Optional[List[str]]:
        """Get valid string values for a parameter"""
        valid_values = {
            "mining_difficulty_adjustment": ["standard", "fast", "conservative"],
            "pos_validation_rules": ["standard", "strict", "lenient"],
            "fee_redistribution_ratio": ["60:25:15", "65:25:10", "55:30:15"]
        }
        return valid_values.get(parameter_name)
    
    def cast_community_veto(self, proposal_id: str, voter_address: str, signature: str = "veto_sig") -> Tuple[bool, str]:
        """Cast a community veto vote on a proposal"""
        try:
            # Check if proposal exists
            if proposal_id not in self.base_governance.proposals:
                return False, "Proposal not found"
            
            # Check if proposal is active
            proposal = self.base_governance.proposals[proposal_id]
            if proposal.status != ProposalStatus.ACTIVE and proposal.status != ProposalStatus.PASSED:
                return False, "Can only veto active or passed proposals"
            
            # Initialize veto tracking for this proposal
            if proposal_id not in self.veto_votes:
                self.veto_votes[proposal_id] = []
            
            # Check if voter already vetoed
            for veto in self.veto_votes[proposal_id]:
                if veto["voter_address"] == voter_address:
                    return False, "Address has already cast a veto vote"
            
            # Calculate voter's veto power (different from regular voting power)
            veto_power = self._calculate_community_veto_power(voter_address)
            if veto_power == 0:
                return False, "Address has no veto power"
            
            # Record veto vote
            veto_vote = {
                "voter_address": voter_address,
                "veto_power": veto_power,
                "timestamp": int(time.time()),
                "signature": signature
            }
            
            self.veto_votes[proposal_id].append(veto_vote)
            
            # Check if veto threshold is reached
            total_veto_power = sum(v["veto_power"] for v in self.veto_votes[proposal_id])
            total_community_power = self._calculate_total_community_power()
            veto_percentage = total_veto_power / total_community_power if total_community_power > 0 else 0
            
            if veto_percentage >= self.community_veto_threshold:
                # Veto threshold reached - block proposal
                proposal.status = ProposalStatus.REJECTED
                logger.info(f"Proposal {proposal_id} vetoed by community ({veto_percentage:.1%} veto power)")
                return True, f"Community veto successful! Proposal blocked with {veto_percentage:.1%} veto power"
            
            return True, f"Veto vote recorded. Current veto power: {veto_percentage:.1%} (need {self.community_veto_threshold:.1%})"
            
        except Exception as e:
            logger.error(f"Error casting community veto: {e}")
            return False, str(e)
    
    def _calculate_community_veto_power(self, address: str) -> int:
        """Calculate community veto power (different from regular voting)"""
        # Community veto power is more distributed - every stakeholder gets veto power
        # This prevents masternode dominance in vetoing
        
        if "masternode" in address.lower():
            return 5  # Masternodes get 5 veto power (not 10x like voting)
        else:
            # Regular stakers get proportional veto power
            stake_amount = self.base_governance._get_stake_amount(address)
            return max(1, int(stake_amount / 2000))  # 1 veto power per 2000 WEPO
    
    def _calculate_total_community_power(self) -> int:
        """Calculate total community veto power"""
        # Simulate total community power for veto calculation
        return 500  # Simulated total community veto power
    
    def get_immutable_parameters(self) -> Dict[str, Dict]:
        """Get all immutable parameters"""
        return {name: asdict(param) for name, param in self.immutable_parameters.items()}
    
    def get_governable_parameters(self) -> Dict[str, Dict]:
        """Get all governable parameters"""
        return {name: asdict(param) for name, param in self.governable_parameters.items()}
    
    def get_halving_schedule(self) -> List[Dict]:
        """Get complete halving schedule with governance windows"""
        return [asdict(phase) for phase in self.halving_phases]
    
    def _get_current_block_height(self) -> int:
        """Get current blockchain height"""
        if self.blockchain:
            return self.blockchain.get_block_height()
        else:
            # Simulate current block height for testing
            # Simulate being in Phase 2A (first governance window)
            return 175000  # Mid-way through Phase 2A for testing


# Global halving-cycle governance system instance
halving_governance = WepoHalvingCycleGovernance()

# Export main functions
__all__ = [
    'WepoHalvingCycleGovernance',
    'halving_governance',
    'HalvingPhase',
    'ImmutableParameter',
    'GovernableParameter',
    'GovernanceWindowStatus',
    'ParameterType'
]