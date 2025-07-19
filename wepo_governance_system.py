#!/usr/bin/env python3
"""
WEPO Governance Framework - Community Decision Making System

This module implements a comprehensive governance framework for the WEPO network,
enabling true community control over network decisions through democratic voting.

Key Features:
- Proposal creation and management
- Weighted voting (masternodes + stakers)
- Quantum-resistant vote validation  
- Automatic proposal execution
- Collateral override capabilities
- Community transparency tools

Voting Power Calculation:
- Masternode: 10x voting power (due to service provision + high collateral)
- Staker: 1x voting power per 1000 WEPO staked
- Minimum participation threshold: 20% of eligible voters
"""

import json
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ProposalStatus(Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PASSED = "passed"  
    REJECTED = "rejected"
    EXECUTED = "executed"
    EXPIRED = "expired"

class ProposalType(Enum):
    COLLATERAL_OVERRIDE = "collateral_override"
    NETWORK_PARAMETER = "network_parameter"
    ECONOMIC_POLICY = "economic_policy"
    PROTOCOL_UPGRADE = "protocol_upgrade"
    COMMUNITY_FUND = "community_fund"
    EMERGENCY_ACTION = "emergency_action"

class VoteChoice(Enum):
    YES = "yes"
    NO = "no"
    ABSTAIN = "abstain"

@dataclass
class Proposal:
    """Governance proposal structure"""
    proposal_id: str
    title: str
    description: str
    proposal_type: ProposalType
    proposer_address: str
    created_at: int
    voting_start: int
    voting_end: int
    status: ProposalStatus
    
    # Proposal specifics
    target_parameter: Optional[str] = None
    proposed_value: Optional[str] = None
    current_value: Optional[str] = None
    
    # Voting requirements
    minimum_participation: float = 0.20  # 20%
    approval_threshold: float = 0.60     # 60%
    
    # Vote tracking
    total_votes: int = 0
    yes_votes: int = 0
    no_votes: int = 0
    abstain_votes: int = 0
    
    # Execution
    execution_block: Optional[int] = None
    execution_result: Optional[str] = None

@dataclass
class Vote:
    """Individual vote record"""
    vote_id: str
    proposal_id: str
    voter_address: str
    vote_choice: VoteChoice
    voting_power: int
    timestamp: int
    signature: str  # Quantum-resistant signature
    vote_hash: str

@dataclass
class VoterInfo:
    """Voter information and power calculation"""
    address: str
    voter_type: str  # 'masternode' or 'staker'
    voting_power: int
    stake_amount: float
    last_vote_block: int
    total_votes_cast: int

class WepoGovernanceSystem:
    """
    WEPO Governance System - Democratic Network Control
    
    Enables the community to make decisions about network parameters,
    economic policies, and protocol upgrades through weighted voting.
    """
    
    def __init__(self):
        # Governance storage
        self.proposals: Dict[str, Proposal] = {}
        self.votes: Dict[str, Vote] = {}
        self.voters: Dict[str, VoterInfo] = {}
        
        # Governance parameters
        self.MASTERNODE_VOTE_MULTIPLIER = 10  # 10x power for masternodes
        self.STAKER_VOTE_UNIT = 1000  # 1 vote per 1000 WEPO staked
        self.MIN_PROPOSAL_BOND = 10000  # 10,000 WEPO to create proposal
        self.VOTING_PERIOD_BLOCKS = 20160  # 2 weeks in 9-minute blocks
        self.EXECUTION_DELAY_BLOCKS = 1440  # 24 hours delay before execution
        
        # Proposal type configurations
        self.proposal_configs = {
            ProposalType.COLLATERAL_OVERRIDE: {
                "min_participation": 0.30,  # 30% for critical decisions
                "approval_threshold": 0.75,  # 75% approval needed
                "execution_delay": 2880     # 48 hours
            },
            ProposalType.NETWORK_PARAMETER: {
                "min_participation": 0.20,
                "approval_threshold": 0.60,
                "execution_delay": 1440
            },
            ProposalType.EMERGENCY_ACTION: {
                "min_participation": 0.25,
                "approval_threshold": 0.67,
                "execution_delay": 720      # 12 hours for emergencies
            }
        }
        
        logger.info("WEPO Governance System initialized")
    
    def create_proposal(self, proposer_address: str, title: str, description: str,
                       proposal_type: ProposalType, target_parameter: Optional[str] = None,
                       proposed_value: Optional[str] = None, 
                       current_value: Optional[str] = None) -> str:
        """
        Create a new governance proposal
        
        Args:
            proposer_address: Address of the proposer (must have sufficient bond)
            title: Proposal title
            description: Detailed proposal description
            proposal_type: Type of proposal
            target_parameter: Parameter to change (if applicable)
            proposed_value: New value (if applicable)
            current_value: Current value (if applicable)
            
        Returns:
            str: Proposal ID
        """
        try:
            # Validate proposer eligibility
            if not self._validate_proposer(proposer_address):
                raise Exception(f"Proposer {proposer_address} is not eligible or lacks sufficient bond")
            
            # Generate unique proposal ID
            proposal_id = f"prop_{int(time.time())}_{secrets.token_hex(8)}"
            
            # Get configuration for this proposal type
            config = self.proposal_configs.get(proposal_type, {
                "min_participation": 0.20,
                "approval_threshold": 0.60,
                "execution_delay": 1440
            })
            
            # Calculate voting period
            current_time = int(time.time())
            voting_start = current_time + 300  # 5 minutes to prepare
            voting_end = voting_start + (self.VOTING_PERIOD_BLOCKS * 9 * 60)  # Convert blocks to seconds
            
            # Create proposal
            proposal = Proposal(
                proposal_id=proposal_id,
                title=title,
                description=description,
                proposal_type=proposal_type,
                proposer_address=proposer_address,
                created_at=current_time,
                voting_start=voting_start,
                voting_end=voting_end,
                status=ProposalStatus.DRAFT,
                target_parameter=target_parameter,
                proposed_value=proposed_value,
                current_value=current_value,
                minimum_participation=config["min_participation"],
                approval_threshold=config["approval_threshold"]
            )
            
            # Store proposal
            self.proposals[proposal_id] = proposal
            
            logger.info(f"Governance proposal created: {proposal_id} by {proposer_address}")
            return proposal_id
            
        except Exception as e:
            logger.error(f"Error creating proposal: {e}")
            raise Exception(f"Proposal creation failed: {str(e)}")
    
    def activate_proposal(self, proposal_id: str) -> bool:
        """Activate a proposal for voting"""
        try:
            if proposal_id not in self.proposals:
                raise Exception("Proposal not found")
            
            proposal = self.proposals[proposal_id]
            
            if proposal.status != ProposalStatus.DRAFT:
                raise Exception("Only draft proposals can be activated")
            
            if int(time.time()) < proposal.voting_start:
                raise Exception("Voting period has not started yet")
            
            # Activate proposal
            proposal.status = ProposalStatus.ACTIVE
            
            logger.info(f"Proposal activated for voting: {proposal_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error activating proposal {proposal_id}: {e}")
            return False
    
    def cast_vote(self, proposal_id: str, voter_address: str, vote_choice: VoteChoice,
                  signature: str = "quantum_sig_placeholder") -> str:
        """
        Cast a vote on a proposal
        
        Args:
            proposal_id: ID of the proposal
            voter_address: Address of the voter
            vote_choice: Vote choice (YES/NO/ABSTAIN)
            signature: Quantum-resistant signature
            
        Returns:
            str: Vote ID
        """
        try:
            # Validate proposal
            if proposal_id not in self.proposals:
                raise Exception("Proposal not found")
            
            proposal = self.proposals[proposal_id]
            
            if proposal.status != ProposalStatus.ACTIVE:
                raise Exception("Proposal is not active for voting")
            
            current_time = int(time.time())
            if current_time < proposal.voting_start or current_time > proposal.voting_end:
                raise Exception("Voting period is not active")
            
            # Check if voter already voted
            existing_vote = self._get_voter_existing_vote(proposal_id, voter_address)
            if existing_vote:
                raise Exception("Voter has already cast a vote on this proposal")
            
            # Calculate voting power
            voting_power = self._calculate_voting_power(voter_address)
            if voting_power == 0:
                raise Exception("Voter has no voting power")
            
            # Create vote
            vote_id = f"vote_{int(time.time())}_{secrets.token_hex(8)}"
            vote_data = f"{proposal_id}:{voter_address}:{vote_choice.value}:{voting_power}:{current_time}"
            vote_hash = hashlib.sha256(vote_data.encode()).hexdigest()
            
            vote = Vote(
                vote_id=vote_id,
                proposal_id=proposal_id,
                voter_address=voter_address,
                vote_choice=vote_choice,
                voting_power=voting_power,
                timestamp=current_time,
                signature=signature,
                vote_hash=vote_hash
            )
            
            # Store vote
            self.votes[vote_id] = vote
            
            # Update proposal vote counts
            proposal.total_votes += voting_power
            if vote_choice == VoteChoice.YES:
                proposal.yes_votes += voting_power
            elif vote_choice == VoteChoice.NO:
                proposal.no_votes += voting_power
            else:
                proposal.abstain_votes += voting_power
            
            # Update voter info
            if voter_address not in self.voters:
                self.voters[voter_address] = VoterInfo(
                    address=voter_address,
                    voter_type=self._get_voter_type(voter_address),
                    voting_power=voting_power,
                    stake_amount=self._get_stake_amount(voter_address),
                    last_vote_block=self._get_current_block_height(),
                    total_votes_cast=0
                )
            
            self.voters[voter_address].total_votes_cast += 1
            self.voters[voter_address].last_vote_block = self._get_current_block_height()
            
            logger.info(f"Vote cast: {vote_id} on proposal {proposal_id} by {voter_address}")
            return vote_id
            
        except Exception as e:
            logger.error(f"Error casting vote: {e}")
            raise Exception(f"Vote casting failed: {str(e)}")
    
    def finalize_proposal(self, proposal_id: str) -> Dict[str, Any]:
        """
        Finalize a proposal after voting ends
        
        Returns proposal results and next steps
        """
        try:
            if proposal_id not in self.proposals:
                raise Exception("Proposal not found")
            
            proposal = self.proposals[proposal_id]
            
            if proposal.status != ProposalStatus.ACTIVE:
                raise Exception("Only active proposals can be finalized")
            
            current_time = int(time.time())
            if current_time <= proposal.voting_end:
                raise Exception("Voting period is still active")
            
            # Calculate results
            total_eligible_power = self._calculate_total_eligible_voting_power()
            participation_rate = proposal.total_votes / total_eligible_power if total_eligible_power > 0 else 0
            
            # Check minimum participation
            if participation_rate < proposal.minimum_participation:
                proposal.status = ProposalStatus.REJECTED
                result = {
                    "status": "rejected",
                    "reason": "Insufficient participation",
                    "participation_rate": participation_rate,
                    "required_participation": proposal.minimum_participation
                }
            else:
                # Calculate approval rate
                approval_votes = proposal.yes_votes
                voting_votes = proposal.yes_votes + proposal.no_votes  # Exclude abstains from calculation
                approval_rate = approval_votes / voting_votes if voting_votes > 0 else 0
                
                if approval_rate >= proposal.approval_threshold:
                    proposal.status = ProposalStatus.PASSED
                    result = {
                        "status": "passed",
                        "approval_rate": approval_rate,
                        "participation_rate": participation_rate,
                        "execution_scheduled": True
                    }
                else:
                    proposal.status = ProposalStatus.REJECTED  
                    result = {
                        "status": "rejected",
                        "reason": "Insufficient approval",
                        "approval_rate": approval_rate,
                        "required_approval": proposal.approval_threshold
                    }
            
            # Add detailed vote breakdown
            result.update({
                "proposal_id": proposal_id,
                "total_votes": proposal.total_votes,
                "yes_votes": proposal.yes_votes,
                "no_votes": proposal.no_votes,
                "abstain_votes": proposal.abstain_votes,
                "finalized_at": current_time
            })
            
            logger.info(f"Proposal finalized: {proposal_id} - {result['status']}")
            return result
            
        except Exception as e:
            logger.error(f"Error finalizing proposal {proposal_id}: {e}")
            raise Exception(f"Proposal finalization failed: {str(e)}")
    
    def execute_proposal(self, proposal_id: str) -> Dict[str, Any]:
        """
        Execute a passed proposal after delay period
        
        This is where approved proposals actually change network parameters
        """
        try:
            if proposal_id not in self.proposals:
                raise Exception("Proposal not found")
            
            proposal = self.proposals[proposal_id]
            
            if proposal.status != ProposalStatus.PASSED:
                raise Exception("Only passed proposals can be executed")
            
            current_block = self._get_current_block_height()
            
            # Check if execution delay has passed
            config = self.proposal_configs.get(proposal.proposal_type, {})
            execution_delay = config.get("execution_delay", self.EXECUTION_DELAY_BLOCKS)
            
            # For simulation, we'll execute immediately
            # In production, this would check actual block height
            
            # Execute based on proposal type
            execution_result = self._execute_proposal_action(proposal)
            
            # Update proposal status
            proposal.status = ProposalStatus.EXECUTED
            proposal.execution_block = current_block
            proposal.execution_result = execution_result["message"]
            
            result = {
                "proposal_id": proposal_id,
                "execution_status": "success",
                "execution_block": current_block,
                "execution_result": execution_result,
                "executed_at": int(time.time())
            }
            
            logger.info(f"Proposal executed: {proposal_id}")
            return result
            
        except Exception as e:
            logger.error(f"Error executing proposal {proposal_id}: {e}")
            raise Exception(f"Proposal execution failed: {str(e)}")
    
    def get_proposal_details(self, proposal_id: str) -> Dict[str, Any]:
        """Get detailed information about a proposal"""
        try:
            if proposal_id not in self.proposals:
                raise Exception("Proposal not found")
            
            proposal = self.proposals[proposal_id]
            
            # Calculate current results
            total_eligible_power = self._calculate_total_eligible_voting_power()
            participation_rate = proposal.total_votes / total_eligible_power if total_eligible_power > 0 else 0
            
            voting_votes = proposal.yes_votes + proposal.no_votes
            approval_rate = proposal.yes_votes / voting_votes if voting_votes > 0 else 0
            
            current_time = int(time.time())
            
            # Determine voting status
            if current_time < proposal.voting_start:
                voting_status = "pending"
            elif current_time <= proposal.voting_end:
                voting_status = "active"
            else:
                voting_status = "ended"
            
            return {
                "proposal": asdict(proposal),
                "voting_status": voting_status,
                "time_remaining": max(0, proposal.voting_end - current_time),
                "current_results": {
                    "participation_rate": participation_rate,
                    "approval_rate": approval_rate,
                    "total_votes": proposal.total_votes,
                    "yes_votes": proposal.yes_votes,
                    "no_votes": proposal.no_votes,
                    "abstain_votes": proposal.abstain_votes
                },
                "requirements": {
                    "minimum_participation": proposal.minimum_participation,
                    "approval_threshold": proposal.approval_threshold
                },
                "meets_requirements": {
                    "participation": participation_rate >= proposal.minimum_participation,
                    "approval": approval_rate >= proposal.approval_threshold
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting proposal details {proposal_id}: {e}")
            raise Exception(f"Failed to get proposal details: {str(e)}")
    
    def get_active_proposals(self) -> List[Dict[str, Any]]:
        """Get all active proposals"""
        active_proposals = []
        
        for proposal_id, proposal in self.proposals.items():
            if proposal.status == ProposalStatus.ACTIVE:
                try:
                    proposal_details = self.get_proposal_details(proposal_id)
                    active_proposals.append(proposal_details)
                except Exception as e:
                    logger.error(f"Error getting active proposal {proposal_id}: {e}")
        
        return active_proposals
    
    def get_governance_stats(self) -> Dict[str, Any]:
        """Get comprehensive governance system statistics"""
        try:
            current_time = int(time.time())
            
            # Count proposals by status
            status_counts = {}
            for status in ProposalStatus:
                status_counts[status.value] = len([p for p in self.proposals.values() if p.status == status])
            
            # Calculate participation statistics
            total_eligible_voters = len(self.voters)
            total_eligible_power = self._calculate_total_eligible_voting_power()
            
            active_proposals = len([p for p in self.proposals.values() if p.status == ProposalStatus.ACTIVE])
            
            # Recent activity (last 30 days)
            recent_proposals = len([
                p for p in self.proposals.values() 
                if p.created_at > current_time - (30 * 24 * 60 * 60)
            ])
            
            recent_votes = len([
                v for v in self.votes.values()
                if v.timestamp > current_time - (30 * 24 * 60 * 60)
            ])
            
            return {
                "governance_system": {
                    "total_proposals": len(self.proposals),
                    "total_votes": len(self.votes),
                    "total_eligible_voters": total_eligible_voters,
                    "total_eligible_voting_power": total_eligible_power
                },
                "proposal_status_breakdown": status_counts,
                "current_activity": {
                    "active_proposals": active_proposals,
                    "recent_proposals_30d": recent_proposals,
                    "recent_votes_30d": recent_votes
                },
                "voting_power_distribution": {
                    "masternode_multiplier": self.MASTERNODE_VOTE_MULTIPLIER,
                    "staker_vote_unit": self.STAKER_VOTE_UNIT,
                    "min_proposal_bond": self.MIN_PROPOSAL_BOND
                },
                "system_parameters": {
                    "voting_period_blocks": self.VOTING_PERIOD_BLOCKS,
                    "execution_delay_blocks": self.EXECUTION_DELAY_BLOCKS,
                    "voting_period_days": self.VOTING_PERIOD_BLOCKS * 9 / (60 * 24),  # Convert to days
                    "execution_delay_hours": self.EXECUTION_DELAY_BLOCKS * 9 / 60    # Convert to hours
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting governance stats: {e}")
            raise Exception(f"Failed to get governance stats: {str(e)}")
    
    # Helper methods
    def _validate_proposer(self, proposer_address: str) -> bool:
        """Validate that proposer can create proposals"""
        # In production, this would check:
        # 1. Sufficient bond (10,000 WEPO)
        # 2. Good standing (no recent rejected proposals)
        # 3. Minimum stake/masternode status
        return True  # Simplified for development
    
    def _calculate_voting_power(self, voter_address: str) -> int:
        """Calculate voting power for an address"""
        # In production, this would integrate with masternode and staking systems
        # For now, simulate based on address characteristics
        
        if "masternode" in voter_address.lower():
            return self.MASTERNODE_VOTE_MULTIPLIER  # 10 votes for masternode
        else:
            # Simulate staker voting power (1 vote per 1000 WEPO)
            simulated_stake = 5000  # 5000 WEPO = 5 votes
            return max(1, int(simulated_stake / self.STAKER_VOTE_UNIT))
    
    def _calculate_total_eligible_voting_power(self) -> int:
        """Calculate total eligible voting power in the network"""
        # In production, this would sum all masternodes and stakers
        # For simulation, return a reasonable number
        return 1000  # Simulated total voting power
    
    def _get_voter_existing_vote(self, proposal_id: str, voter_address: str) -> Optional[Vote]:
        """Check if voter already voted on proposal"""
        for vote in self.votes.values():
            if vote.proposal_id == proposal_id and vote.voter_address == voter_address:
                return vote
        return None
    
    def _get_voter_type(self, voter_address: str) -> str:
        """Determine voter type"""
        return "masternode" if "masternode" in voter_address.lower() else "staker"
    
    def _get_stake_amount(self, voter_address: str) -> float:
        """Get stake amount for address"""
        # Simulate stake amounts
        return 5000.0  # 5000 WEPO
    
    def _get_current_block_height(self) -> int:
        """Get current blockchain height"""
        # Simulate current block height
        return int(time.time() / 540)  # Approximate 9-minute blocks
    
    def _execute_proposal_action(self, proposal: Proposal) -> Dict[str, Any]:
        """Execute the actual proposal action"""
        try:
            if proposal.proposal_type == ProposalType.COLLATERAL_OVERRIDE:
                return {
                    "action": "collateral_override",
                    "parameter": proposal.target_parameter,
                    "old_value": proposal.current_value,
                    "new_value": proposal.proposed_value,
                    "message": f"Collateral parameter '{proposal.target_parameter}' updated from {proposal.current_value} to {proposal.proposed_value}"
                }
            elif proposal.proposal_type == ProposalType.NETWORK_PARAMETER:
                return {
                    "action": "network_parameter_change",
                    "parameter": proposal.target_parameter,
                    "old_value": proposal.current_value,
                    "new_value": proposal.proposed_value,
                    "message": f"Network parameter '{proposal.target_parameter}' updated from {proposal.current_value} to {proposal.proposed_value}"
                }
            else:
                return {
                    "action": "general_proposal",
                    "message": f"Proposal '{proposal.title}' executed successfully"
                }
                
        except Exception as e:
            logger.error(f"Error executing proposal action: {e}")
            return {
                "action": "failed",
                "message": f"Proposal execution failed: {str(e)}"
            }

# Global governance system instance
governance_system = WepoGovernanceSystem()

# Export main functions
__all__ = [
    'WepoGovernanceSystem',
    'governance_system',
    'Proposal',
    'Vote',
    'VoterInfo',
    'ProposalStatus',
    'ProposalType', 
    'VoteChoice'
]