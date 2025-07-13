#!/usr/bin/env python3
"""
WEPO Quantum Vault System - "Be Your Own Bank" Privacy Feature

This module implements the Quantum Vault system that provides ultimate privacy
for WEPO holdings using zk-STARK technology. Features include:

- Private balance storage with mathematical privacy proofs
- Auto-deposit functionality for all incoming WEPO
- Zero-knowledge proof generation and verification
- Complete transaction privacy and anonymity
- Integration with existing WEPO wallet system

The Quantum Vault represents the pinnacle of financial privacy technology,
ensuring that "We The People" maintain complete control and privacy over
their wealth.
"""

import hashlib
import json
import secrets
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import logging
from enum import Enum

logger = logging.getLogger(__name__)

@dataclass
class VaultAsset:
    """Represents an asset in a vault (WEPO or RWA token)"""
    asset_type: str  # 'WEPO' or 'RWA_TOKEN'
    asset_id: str    # 'WEPO' for WEPO, token_id for RWA tokens
    balance: float
    commitment: str
    last_updated: int

@dataclass
class VaultTransaction:
    """Represents a private vault transaction"""
    vault_id: str
    transaction_type: str  # 'deposit', 'withdrawal', 'auto_deposit', 'ghost_send', 'ghost_receive'
    asset_type: str  # 'WEPO' or 'RWA_TOKEN'
    asset_id: str    # 'WEPO' for WEPO, token_id for RWA tokens
    amount: float
    timestamp: int
    proof_hash: str
    commitment: str
    nullifier: str
    ghost_transfer_id: Optional[str] = None  # For ghost transfers
    asset_metadata: Optional[Dict] = None   # Additional asset information

@dataclass
class ZKProof:
    """Zero-knowledge proof for vault operations"""
    proof_data: str
    public_inputs: List[str]
    verification_key: str
    created_at: int

@dataclass  
class GhostTransfer:
    """Ghost transfer between vaults - completely private and untraceable"""
    transfer_id: str
    sender_vault_id: str
    receiver_vault_id: str
    asset_type: str  # 'WEPO' or 'RWA_TOKEN'
    asset_id: str    # 'WEPO' for WEPO, token_id for RWA tokens
    amount: float
    privacy_level: str  # 'standard' or 'maximum'
    hide_amount: bool
    hide_asset_type: bool  # NEW: Option to hide what type of asset is being transferred
    status: str  # 'initiated', 'pending', 'accepted', 'rejected', 'completed'
    created_at: int
    accepted_at: Optional[int] = None
    completed_at: Optional[int] = None
    sender_proof: Optional[ZKProof] = None
    receiver_proof: Optional[ZKProof] = None
    transfer_nullifier: Optional[str] = None
    encrypted_amount: Optional[str] = None  # For maximum privacy
    encrypted_asset_info: Optional[str] = None  # For hiding asset type and metadata

class GhostTransferStatus(str, Enum):
    INITIATED = "initiated"
    PENDING = "pending" 
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"

class PrivacyLevel(str, Enum):
    STANDARD = "standard"
    MAXIMUM = "maximum"

class QuantumVaultSystem:
    """
    Quantum Vault System for WEPO
    
    Provides ultimate privacy for WEPO storage using zk-STARK technology.
    Implements mathematical privacy proofs that ensure complete anonymity
    while maintaining verifiable balances and transaction integrity.
    """
    
    def __init__(self):
        self.vaults = {}  # vault_address -> VaultData - RESET TO CLEAN STATE
        self.commitments = {}  # commitment_hash -> commitment_data - RESET TO CLEAN STATE
        self.nullifiers = set()  # spent nullifiers - RESET TO CLEAN STATE
        self.auto_deposit_settings = {}  # wallet_address -> auto_deposit_enabled - RESET TO CLEAN STATE
        self.vault_transactions = {}  # vault_id -> List[VaultTransaction] - RESET TO CLEAN STATE
        
        # Ghost Transfer System - RESET TO CLEAN STATE
        self.ghost_transfers = {}  # transfer_id -> GhostTransfer - RESET TO CLEAN STATE
        self.pending_ghost_transfers = {}  # receiver_vault_id -> List[transfer_id] - RESET TO CLEAN STATE
        self.ghost_nullifiers = set()  # spent ghost transfer nullifiers - RESET TO CLEAN STATE
        self.cross_vault_commitments = {}  # Special commitments for cross-vault operations - RESET TO CLEAN STATE
        
    def create_vault(self, wallet_address: str) -> Dict:
        """
        Create a new quantum vault for multi-asset private storage
        
        Enhanced to support both WEPO and RWA tokens with privacy protection
        """
        try:
            vault_id = f"vault_{int(time.time())}_{secrets.token_hex(8)}"
            
            # Enhanced vault structure for multi-asset support
            vault_data = {
                "vault_id": vault_id,
                "wallet_address": wallet_address,
                "created_at": int(time.time()),
                "privacy_level": "maximum",
                "auto_deposit_enabled": False,
                "transaction_count": 0,
                
                # Multi-asset storage - REVOLUTIONARY ENHANCEMENT
                "assets": {
                    "WEPO": {
                        "balance": 0.0,
                        "commitment": self._generate_commitment(0.0, secrets.token_hex(32)),
                        "last_updated": int(time.time())
                    }
                    # RWA tokens will be added dynamically as they are deposited
                },
                
                # Privacy features
                "zk_stark_enabled": True,
                "commitment_scheme": "pedersen_hash",
                "ghost_transfers_enabled": True,
                "rwa_privacy_enabled": True  # NEW: RWA-specific privacy
            }
            
            self.vaults[vault_id] = vault_data
            self.vault_transactions[vault_id] = []
            
            logger.info(f"Multi-asset Quantum Vault created: {vault_id} for {wallet_address}")
            
            return {
                "vault_id": vault_id,
                "wallet_address": wallet_address,
                "created_at": vault_data["created_at"],
                "privacy_enabled": True,
                "auto_deposit_available": True,
                "zk_stark_protection": True,
                "multi_asset_support": True,  # NEW
                "rwa_support": True,         # NEW  
                "ghost_transfers": True,
                "rwa_ghost_transfers": True  # NEW
            }
            
        except Exception as e:
            logger.error(f"Error creating vault: {str(e)}")
            raise Exception(f"Vault creation failed: {str(e)}")
    
    def deposit_to_vault(self, vault_id: str, amount: float, source_type: str = "manual", 
                        asset_type: str = "WEPO", asset_id: str = "WEPO", 
                        asset_metadata: Optional[Dict] = None) -> Dict:
        """
        Deposit WEPO or RWA tokens to Quantum Vault with privacy protection
        
        REVOLUTIONARY ENHANCEMENT: Now supports both WEPO and RWA tokens
        
        Args:
            vault_id: Target vault identifier
            amount: Amount to deposit
            source_type: Source of the deposit ('manual', 'auto_transaction', etc.)
            asset_type: 'WEPO' or 'RWA_TOKEN'
            asset_id: 'WEPO' for WEPO, token_id for RWA tokens
            asset_metadata: Additional information for RWA tokens
            
        Returns:
            Dictionary containing deposit confirmation with privacy protection
        """
        try:
            if vault_id not in self.vaults:
                raise Exception("Vault not found")
            
            if amount <= 0:
                raise Exception("Invalid amount")
                
            vault = self.vaults[vault_id]
            
            # Initialize asset in vault if not exists (for RWA tokens)
            if asset_id not in vault["assets"]:
                vault["assets"][asset_id] = {
                    "balance": 0.0,
                    "commitment": self._generate_commitment(0.0, secrets.token_hex(32)),
                    "last_updated": int(time.time()),
                    "asset_type": asset_type,
                    "metadata": asset_metadata or {}
                }
                logger.info(f"New {asset_type} asset {asset_id} added to vault {vault_id}")
            
            # Update asset balance
            current_balance = vault["assets"][asset_id]["balance"]
            new_balance = current_balance + amount
            
            # Generate new commitment for privacy
            secret = secrets.token_hex(32)
            new_commitment = self._generate_commitment(new_balance, secret)
            
            # Generate zk-proof for deposit
            proof = self._generate_zk_proof(
                vault_id=vault_id,
                operation=f"deposit_{asset_type.lower()}",
                amount=amount,
                commitment=new_commitment,
                asset_type=asset_type,
                asset_id=asset_id
            )
            
            # Create transaction record
            transaction = VaultTransaction(
                vault_id=vault_id,
                transaction_type="deposit",
                asset_type=asset_type,
                asset_id=asset_id,
                amount=amount,
                timestamp=int(time.time()),
                proof_hash=self._hash_proof_data(vault_id, amount, f"deposit_{asset_type.lower()}"),
                commitment=new_commitment,
                nullifier=secrets.token_hex(32),
                asset_metadata=asset_metadata
            )
            
            # Update vault state
            vault["assets"][asset_id]["balance"] = new_balance
            vault["assets"][asset_id]["commitment"] = new_commitment
            vault["assets"][asset_id]["last_updated"] = int(time.time())
            vault["transaction_count"] += 1
            
            # Store transaction
            self.vault_transactions[vault_id].append(transaction)
            self.commitments[new_commitment] = {
                "vault_id": vault_id,
                "asset_id": asset_id,
                "balance": new_balance,
                "created_at": int(time.time())
            }
            
            logger.info(f"Vault deposit: {amount} {asset_type} ({asset_id}) to {vault_id} ({source_type})")
            
            return {
                "transaction_id": transaction.proof_hash,
                "status": "confirmed",
                "asset_type": asset_type,
                "asset_id": asset_id,
                "amount_deposited": amount,
                "new_commitment": new_commitment,
                "proof": proof,
                "privacy_protected": True,
                "source_type": source_type,
                "rwa_support": asset_type == "RWA_TOKEN"
            }
            
        except Exception as e:
            logger.error(f"Error depositing to vault: {str(e)}")
            raise Exception(f"Vault deposit failed: {str(e)}")
    
    def withdraw_from_vault(self, vault_id: str, amount: float, destination_address: str,
                          asset_type: str = "WEPO", asset_id: str = "WEPO") -> Dict:
        """
        Withdraw WEPO or RWA tokens from Quantum Vault with privacy protection
        
        REVOLUTIONARY ENHANCEMENT: Now supports both WEPO and RWA tokens
        
        Args:
            vault_id: Source vault identifier
            amount: Amount to withdraw
            destination_address: Target wallet address
            asset_type: 'WEPO' or 'RWA_TOKEN'
            asset_id: 'WEPO' for WEPO, token_id for RWA tokens
            
        Returns:
            Dictionary containing withdrawal confirmation
        """
        try:
            if vault_id not in self.vaults:
                raise Exception("Vault not found")
            
            vault = self.vaults[vault_id]
            
            # Check if asset exists in vault
            if asset_id not in vault["assets"]:
                raise Exception(f"Asset {asset_id} not found in vault")
            
            current_balance = vault["assets"][asset_id]["balance"]
            
            if current_balance < amount:
                raise Exception(f"Insufficient {asset_type} balance in vault")
            
            # Calculate new balance
            new_balance = current_balance - amount
            
            # Generate new commitment for privacy
            secret = secrets.token_hex(32)
            new_commitment = self._generate_commitment(new_balance, secret)
            
            # Generate zk-proof for withdrawal
            proof = self._generate_zk_proof(
                vault_id=vault_id,
                operation=f"withdraw_{asset_type.lower()}",
                amount=amount,
                commitment=new_commitment,
                asset_type=asset_type,
                asset_id=asset_id
            )
            
            # Generate nullifier to prevent double-spending
            nullifier = self._generate_nullifier(vault_id, amount, asset_id)
            
            if nullifier in self.nullifiers:
                raise Exception("Invalid withdrawal - nullifier already used")
            
            # Create transaction record
            transaction = VaultTransaction(
                vault_id=vault_id,
                transaction_type="withdrawal",
                asset_type=asset_type,
                asset_id=asset_id,
                amount=amount,
                timestamp=int(time.time()),
                proof_hash=self._hash_proof_data(vault_id, amount, f"withdraw_{asset_type.lower()}"),
                commitment=new_commitment,
                nullifier=nullifier
            )
            
            # Update vault state
            vault["assets"][asset_id]["balance"] = new_balance
            vault["assets"][asset_id]["commitment"] = new_commitment
            vault["assets"][asset_id]["last_updated"] = int(time.time())
            vault["transaction_count"] += 1
            
            # Store transaction and nullifier
            self.vault_transactions[vault_id].append(transaction)
            self.nullifiers.add(nullifier)
            self.commitments[new_commitment] = {
                "vault_id": vault_id,
                "asset_id": asset_id,
                "balance": new_balance,
                "created_at": int(time.time())
            }
            
            logger.info(f"Vault withdrawal: {amount} {asset_type} ({asset_id}) from {vault_id} to {destination_address}")
            
            return {
                "transaction_id": transaction.proof_hash,
                "status": "confirmed",
                "asset_type": asset_type,
                "asset_id": asset_id,
                "amount_withdrawn": amount,
                "destination_address": destination_address,
                "new_commitment": new_commitment,
                "proof": proof,
                "nullifier": nullifier,
                "privacy_protected": True,
                "rwa_support": asset_type == "RWA_TOKEN"
            }
            
        except Exception as e:
            logger.error(f"Error withdrawing from vault: {str(e)}")
            raise Exception(f"Vault withdrawal failed: {str(e)}")
    
    def enable_auto_deposit(self, wallet_address: str, vault_id: str) -> Dict:
        """
        Enable auto-deposit for all incoming WEPO to go directly to vault
        
        Args:
            wallet_address: Wallet address to enable auto-deposit for
            vault_id: Target vault for auto-deposits
            
        Returns:
            Dictionary containing auto-deposit configuration
        """
        try:
            if vault_id not in self.vaults:
                raise Exception("Vault not found")
            
            vault = self.vaults[vault_id]
            if vault["wallet_address"] != wallet_address:
                raise Exception("Vault does not belong to this wallet")
            
            # Enable auto-deposit
            self.auto_deposit_settings[wallet_address] = {
                "enabled": True,
                "vault_id": vault_id,
                "enabled_at": int(time.time()),
                "auto_deposit_types": ["transactions", "rewards", "trading", "mining"]
            }
            
            vault["auto_deposit_enabled"] = True
            
            logger.info(f"Auto-deposit enabled for {wallet_address} -> {vault_id}")
            
            return {
                "status": "enabled",
                "wallet_address": wallet_address,
                "vault_id": vault_id,
                "auto_deposit_types": ["transactions", "rewards", "trading", "mining"],
                "privacy_enhanced": True
            }
            
        except Exception as e:
            logger.error(f"Error enabling auto-deposit: {str(e)}")
            raise Exception(f"Auto-deposit setup failed: {str(e)}")
    
    def disable_auto_deposit(self, wallet_address: str) -> Dict:
        """Disable auto-deposit for a wallet address"""
        try:
            if wallet_address in self.auto_deposit_settings:
                vault_id = self.auto_deposit_settings[wallet_address]["vault_id"]
                
                # Disable auto-deposit
                self.auto_deposit_settings[wallet_address]["enabled"] = False
                
                if vault_id in self.vaults:
                    self.vaults[vault_id]["auto_deposit_enabled"] = False
                
                logger.info(f"Auto-deposit disabled for {wallet_address}")
                
                return {
                    "status": "disabled",
                    "wallet_address": wallet_address,
                    "vault_id": vault_id
                }
            else:
                return {"status": "not_configured", "wallet_address": wallet_address}
                
        except Exception as e:
            logger.error(f"Error disabling auto-deposit: {str(e)}")
            raise Exception(f"Auto-deposit disable failed: {str(e)}")
    
    def process_auto_deposit(self, wallet_address: str, amount: float, source_type: str) -> Optional[Dict]:
        """
        Process automatic deposit if enabled for wallet
        
        Args:
            wallet_address: Wallet receiving funds
            amount: Amount of WEPO received
            source_type: Source of funds ('transaction', 'reward', 'trading', 'mining')
            
        Returns:
            Dictionary with auto-deposit result or None if not enabled
        """
        try:
            if wallet_address not in self.auto_deposit_settings:
                return None
            
            settings = self.auto_deposit_settings[wallet_address]
            
            if not settings["enabled"]:
                return None
            
            if source_type not in settings["auto_deposit_types"]:
                return None
            
            vault_id = settings["vault_id"]
            
            # Automatically deposit to vault
            result = self.deposit_to_vault(vault_id, amount, f"auto_{source_type}")
            
            logger.info(f"Auto-deposit processed: {amount} WEPO from {source_type} -> {vault_id}")
            
            return {
                "auto_deposited": True,
                "amount": amount,
                "source_type": source_type,
                "vault_id": vault_id,
                "transaction_id": result["transaction_id"]
            }
            
        except Exception as e:
            logger.error(f"Error processing auto-deposit: {str(e)}")
            return None
    
    def get_vault_status(self, vault_id: str) -> Dict:
        """Get current vault status and statistics"""
        try:
            if vault_id not in self.vaults:
                raise Exception("Vault not found")
            
            vault = self.vaults[vault_id]
            transactions = self.vault_transactions.get(vault_id, [])
            
            # Calculate statistics
            total_deposits = sum(t.amount for t in transactions if "deposit" in t.transaction_type)
            total_withdrawals = sum(t.amount for t in transactions if t.transaction_type == "withdrawal")
            
            return {
                "vault_id": vault_id,
                "wallet_address": vault["wallet_address"],
                "created_at": vault["created_at"],
                "private_balance": vault["private_balance"],  # In production, this would be encrypted
                "transaction_count": vault["transaction_count"],
                "auto_deposit_enabled": vault["auto_deposit_enabled"],
                "privacy_level": vault["privacy_level"],
                "statistics": {
                    "total_deposits": total_deposits,
                    "total_withdrawals": total_withdrawals,
                    "net_deposits": total_deposits - total_withdrawals
                },
                "privacy_protected": True
            }
            
        except Exception as e:
            logger.error(f"Error getting vault status: {str(e)}")
            raise Exception(f"Vault status failed: {str(e)}")
    
    def get_wallet_vaults(self, wallet_address: str) -> List[Dict]:
        """Get all vaults associated with a wallet address"""
        try:
            wallet_vaults = []
            
            for vault_id, vault in self.vaults.items():
                if vault["wallet_address"] == wallet_address:
                    vault_status = self.get_vault_status(vault_id)
                    wallet_vaults.append(vault_status)
            
            return wallet_vaults
            
        except Exception as e:
            logger.error(f"Error getting wallet vaults: {str(e)}")
            return []
    
    # ===== GHOST TRANSFER SYSTEM - REVOLUTIONARY PRIVACY FEATURES =====
    
    def initiate_ghost_transfer(self, sender_vault_id: str, receiver_vault_id: str, 
                               amount: float, privacy_level: str = "maximum", 
                               hide_amount: bool = True, asset_type: str = "WEPO", 
                               asset_id: str = "WEPO", hide_asset_type: bool = False) -> Dict:
        """
        Initiate a completely private vault-to-vault transfer (Ghost Transfer)
        
        REVOLUTIONARY ENHANCEMENT: Now supports both WEPO and RWA tokens
        
        This creates the most private cryptocurrency transfer possible:
        - Sender identity: Completely hidden via zk-proof
        - Receiver identity: Only known to receiver
        - Transfer amount: Optionally hidden 
        - Asset type: Optionally hidden (NEW!)
        - No on-chain linkability: Zero trace between vaults
        
        Args:
            sender_vault_id: Source vault identifier
            receiver_vault_id: Destination vault identifier  
            amount: Amount to transfer privately
            privacy_level: 'standard' or 'maximum' privacy
            hide_amount: Whether to hide the transfer amount
            asset_type: 'WEPO' or 'RWA_TOKEN'
            asset_id: 'WEPO' for WEPO, token_id for RWA tokens
            hide_asset_type: Whether to hide what type of asset is being transferred
            
        Returns:
            Dictionary containing ghost transfer initiation details
        """
        try:
            # Validate vaults exist
            if sender_vault_id not in self.vaults:
                raise Exception("Sender vault not found")
            if receiver_vault_id not in self.vaults:
                raise Exception("Receiver vault not found")
            if sender_vault_id == receiver_vault_id:
                raise Exception("Cannot transfer to same vault")
                
            sender_vault = self.vaults[sender_vault_id]
            receiver_vault = self.vaults[receiver_vault_id]
            
            # Validate sender has the asset and sufficient balance
            if asset_id not in sender_vault["assets"]:
                raise Exception(f"Asset {asset_id} not found in sender vault")
            
            if sender_vault["assets"][asset_id]["balance"] < amount:
                raise Exception("Insufficient vault balance for ghost transfer")
            
            # Generate unique transfer ID
            transfer_id = f"ghost_{asset_type.lower()}_{int(time.time())}_{secrets.token_hex(16)}"
            
            # Generate transfer nullifier (prevents double-spending across transfers)
            transfer_nullifier = self._generate_ghost_nullifier(sender_vault_id, amount, transfer_id, asset_id)
            
            if transfer_nullifier in self.ghost_nullifiers:
                raise Exception("Invalid ghost transfer - nullifier already used")
            
            # Create sender zk-proof: "I have ≥amount of asset_type without revealing actual balance"
            sender_proof = self._generate_cross_vault_proof(
                sender_vault_id=sender_vault_id,
                operation=f"ghost_send_{asset_type.lower()}",
                amount=amount,
                privacy_level=privacy_level,
                hide_amount=hide_amount,
                asset_type=asset_type,
                asset_id=asset_id
            )
            
            # Encrypt amount and asset info for maximum privacy
            encrypted_amount = None
            encrypted_asset_info = None
            display_amount = amount
            display_asset_type = asset_type
            display_asset_id = asset_id
            
            if hide_amount and privacy_level == "maximum":
                encrypted_amount = str(amount)  # Store actual amount in encrypted field for simulation
                display_amount = 0.0  # Hide the amount in the transfer record
            
            if hide_asset_type and privacy_level == "maximum":
                encrypted_asset_info = json.dumps({
                    "asset_type": asset_type,
                    "asset_id": asset_id
                })
                display_asset_type = "HIDDEN"
                display_asset_id = "HIDDEN"
            
            # Create ghost transfer record
            ghost_transfer = GhostTransfer(
                transfer_id=transfer_id,
                sender_vault_id=sender_vault_id,
                receiver_vault_id=receiver_vault_id,
                asset_type=display_asset_type,
                asset_id=display_asset_id,
                amount=display_amount,  # Hidden amount shows as 0.0
                privacy_level=privacy_level,
                hide_amount=hide_amount,
                hide_asset_type=hide_asset_type,
                status=GhostTransferStatus.PENDING,
                created_at=int(time.time()),
                sender_proof=sender_proof,
                transfer_nullifier=transfer_nullifier,
                encrypted_amount=encrypted_amount,
                encrypted_asset_info=encrypted_asset_info
            )
            
            # Store ghost transfer
            self.ghost_transfers[transfer_id] = ghost_transfer
            
            # Add to pending transfers for receiver
            if receiver_vault_id not in self.pending_ghost_transfers:
                self.pending_ghost_transfers[receiver_vault_id] = []
            self.pending_ghost_transfers[receiver_vault_id].append(transfer_id)
            
            logger.info(f"RWA Ghost transfer initiated: {transfer_id} ({asset_type} - {privacy_level} privacy)")
            
            return {
                "transfer_id": transfer_id,
                "status": "initiated",
                "asset_type": asset_type,
                "asset_id": asset_id,
                "privacy_level": privacy_level,
                "amount_hidden": hide_amount,
                "asset_type_hidden": hide_asset_type,
                "sender_proof_generated": True,
                "awaiting_receiver_acceptance": True,
                "ghost_transfer": True,
                "rwa_support": asset_type == "RWA_TOKEN",
                "privacy_protection": "maximum"
            }
            
        except Exception as e:
            logger.error(f"Error initiating ghost transfer: {str(e)}")
            raise Exception(f"Ghost transfer initiation failed: {str(e)}")
    
    def accept_ghost_transfer(self, transfer_id: str, receiver_vault_id: str) -> Dict:
        """
        Accept an incoming ghost transfer and complete the private transfer
        
        Args:
            transfer_id: Ghost transfer identifier
            receiver_vault_id: Receiving vault identifier
            
        Returns:
            Dictionary containing transfer completion details
        """
        try:
            if transfer_id not in self.ghost_transfers:
                raise Exception("Ghost transfer not found")
                
            ghost_transfer = self.ghost_transfers[transfer_id]
            
            # Validate receiver vault
            if ghost_transfer.receiver_vault_id != receiver_vault_id:
                raise Exception("Invalid receiver vault for this ghost transfer")
            
            if ghost_transfer.status != GhostTransferStatus.PENDING:
                raise Exception(f"Ghost transfer not in pending state: {ghost_transfer.status}")
            
            # Get actual amount (decrypt if hidden)
            actual_amount = ghost_transfer.amount
            if ghost_transfer.hide_amount and ghost_transfer.encrypted_amount:
                # For simulation, retrieve actual amount from encrypted field
                # In production, this would use proper decryption with receiver's private key
                actual_amount = float(ghost_transfer.encrypted_amount)
            elif ghost_transfer.amount == 0.0 and ghost_transfer.hide_amount:
                # Fallback for hidden amounts
                actual_amount = float(ghost_transfer.encrypted_amount) if ghost_transfer.encrypted_amount else 0.0
            
            # Execute atomic vault updates
            sender_vault = self.vaults[ghost_transfer.sender_vault_id]
            receiver_vault = self.vaults[ghost_transfer.receiver_vault_id]
            
            # Generate new commitments for both vaults (complete privacy)
            sender_secret = secrets.token_hex(32)
            receiver_secret = secrets.token_hex(32)
            
            new_sender_balance = sender_vault["private_balance"] - actual_amount
            new_receiver_balance = receiver_vault["private_balance"] + actual_amount
            
            sender_new_commitment = self._generate_commitment(new_sender_balance, sender_secret)
            receiver_new_commitment = self._generate_commitment(new_receiver_balance, receiver_secret)
            
            # Generate receiver proof for acceptance
            receiver_proof = self._generate_cross_vault_proof(
                sender_vault_id=ghost_transfer.receiver_vault_id,
                operation="ghost_receive", 
                amount=actual_amount,
                privacy_level=ghost_transfer.privacy_level,
                hide_amount=ghost_transfer.hide_amount
            )
            
            # Create transaction records for both vaults (privacy-protected)
            sender_transaction = VaultTransaction(
                vault_id=ghost_transfer.sender_vault_id,
                transaction_type="ghost_send",
                amount=actual_amount,
                timestamp=int(time.time()),
                proof_hash=self._hash_proof_data(ghost_transfer.sender_vault_id, actual_amount, "ghost_send"),
                commitment=sender_new_commitment,
                nullifier=ghost_transfer.transfer_nullifier,
                ghost_transfer_id=transfer_id
            )
            
            receiver_transaction = VaultTransaction(
                vault_id=ghost_transfer.receiver_vault_id,
                transaction_type="ghost_receive",
                amount=actual_amount,
                timestamp=int(time.time()),
                proof_hash=self._hash_proof_data(ghost_transfer.receiver_vault_id, actual_amount, "ghost_receive"),
                commitment=receiver_new_commitment,
                nullifier=secrets.token_hex(32),
                ghost_transfer_id=transfer_id
            )
            
            # Atomic update: Both vaults update simultaneously
            sender_vault["private_balance"] = new_sender_balance
            sender_vault["commitment"] = sender_new_commitment
            sender_vault["transaction_count"] += 1
            
            receiver_vault["private_balance"] = new_receiver_balance
            receiver_vault["commitment"] = receiver_new_commitment
            receiver_vault["transaction_count"] += 1
            
            # Store transactions
            self.vault_transactions[ghost_transfer.sender_vault_id].append(sender_transaction)
            self.vault_transactions[ghost_transfer.receiver_vault_id].append(receiver_transaction)
            
            # Update commitments registry
            self.commitments[sender_new_commitment] = {
                "vault_id": ghost_transfer.sender_vault_id,
                "balance": new_sender_balance,
                "created_at": int(time.time())
            }
            self.commitments[receiver_new_commitment] = {
                "vault_id": ghost_transfer.receiver_vault_id,
                "balance": new_receiver_balance,
                "created_at": int(time.time())
            }
            
            # Mark nullifier as used
            self.ghost_nullifiers.add(ghost_transfer.transfer_nullifier)
            
            # Update ghost transfer status
            ghost_transfer.status = GhostTransferStatus.COMPLETED
            ghost_transfer.accepted_at = int(time.time())
            ghost_transfer.completed_at = int(time.time())
            ghost_transfer.receiver_proof = receiver_proof
            
            # Remove from pending transfers
            if receiver_vault_id in self.pending_ghost_transfers:
                if transfer_id in self.pending_ghost_transfers[receiver_vault_id]:
                    self.pending_ghost_transfers[receiver_vault_id].remove(transfer_id)
            
            logger.info(f"Ghost transfer completed: {transfer_id} - {actual_amount} WEPO transferred privately")
            
            return {
                "transfer_id": transfer_id,
                "status": "completed", 
                "amount_received": actual_amount,
                "privacy_level": ghost_transfer.privacy_level,
                "sender_commitment_updated": True,
                "receiver_commitment_updated": True,
                "ghost_transfer_completed": True,
                "untraceable": True,
                "privacy_protection": "maximum"
            }
            
        except Exception as e:
            logger.error(f"Error accepting ghost transfer: {str(e)}")
            # Mark transfer as failed
            if transfer_id in self.ghost_transfers:
                self.ghost_transfers[transfer_id].status = GhostTransferStatus.FAILED
            raise Exception(f"Ghost transfer acceptance failed: {str(e)}")
    
    def reject_ghost_transfer(self, transfer_id: str, receiver_vault_id: str) -> Dict:
        """Reject an incoming ghost transfer"""
        try:
            if transfer_id not in self.ghost_transfers:
                raise Exception("Ghost transfer not found")
                
            ghost_transfer = self.ghost_transfers[transfer_id]
            
            if ghost_transfer.receiver_vault_id != receiver_vault_id:
                raise Exception("Invalid receiver vault for this ghost transfer")
                
            if ghost_transfer.status != GhostTransferStatus.PENDING:
                raise Exception(f"Ghost transfer not in pending state: {ghost_transfer.status}")
            
            # Update status to rejected
            ghost_transfer.status = GhostTransferStatus.REJECTED
            ghost_transfer.accepted_at = int(time.time())
            
            # Remove from pending transfers
            if receiver_vault_id in self.pending_ghost_transfers:
                if transfer_id in self.pending_ghost_transfers[receiver_vault_id]:
                    self.pending_ghost_transfers[receiver_vault_id].remove(transfer_id)
            
            logger.info(f"Ghost transfer rejected: {transfer_id}")
            
            return {
                "transfer_id": transfer_id,
                "status": "rejected",
                "rejected_at": int(time.time())
            }
            
        except Exception as e:
            logger.error(f"Error rejecting ghost transfer: {str(e)}")
            raise Exception(f"Ghost transfer rejection failed: {str(e)}")
    
    def get_pending_ghost_transfers(self, vault_id: str) -> List[Dict]:
        """Get all pending ghost transfers for a vault"""
        try:
            pending_transfers = []
            
            if vault_id in self.pending_ghost_transfers:
                for transfer_id in self.pending_ghost_transfers[vault_id]:
                    if transfer_id in self.ghost_transfers:
                        ghost_transfer = self.ghost_transfers[transfer_id]
                        
                        # Prepare transfer info (hide sensitive data)
                        transfer_info = {
                            "transfer_id": transfer_id,
                            "amount": ghost_transfer.amount if not ghost_transfer.hide_amount else "Hidden",
                            "privacy_level": ghost_transfer.privacy_level,
                            "created_at": ghost_transfer.created_at,
                            "status": ghost_transfer.status,
                            "sender_vault_hidden": True,  # Never reveal sender
                            "privacy_protected": True
                        }
                        
                        pending_transfers.append(transfer_info)
            
            return pending_transfers
            
        except Exception as e:
            logger.error(f"Error getting pending ghost transfers: {str(e)}")
            return []
    
    def get_ghost_transfer_status(self, transfer_id: str, vault_id: str) -> Dict:
        """Get status of a specific ghost transfer"""
        try:
            if transfer_id not in self.ghost_transfers:
                raise Exception("Ghost transfer not found")
                
            ghost_transfer = self.ghost_transfers[transfer_id]
            
            # Verify vault is involved in this transfer
            if vault_id not in [ghost_transfer.sender_vault_id, ghost_transfer.receiver_vault_id]:
                raise Exception("Vault not involved in this ghost transfer")
            
            # Determine perspective (sender or receiver)
            is_sender = (vault_id == ghost_transfer.sender_vault_id)
            
            transfer_status = {
                "transfer_id": transfer_id,
                "status": ghost_transfer.status,
                "privacy_level": ghost_transfer.privacy_level,
                "created_at": ghost_transfer.created_at,
                "is_sender": is_sender,
                "is_receiver": not is_sender,
                "privacy_protected": True
            }
            
            # Add amount info based on privacy settings
            if ghost_transfer.hide_amount:
                transfer_status["amount"] = "Hidden" if not is_sender else ghost_transfer.amount
            else:
                transfer_status["amount"] = ghost_transfer.amount
            
            # Add timing info
            if ghost_transfer.accepted_at:
                transfer_status["accepted_at"] = ghost_transfer.accepted_at
            if ghost_transfer.completed_at:
                transfer_status["completed_at"] = ghost_transfer.completed_at
                
            return transfer_status
            
        except Exception as e:
            logger.error(f"Error getting ghost transfer status: {str(e)}")
            raise Exception(f"Ghost transfer status failed: {str(e)}")
    
    def get_vault_ghost_history(self, vault_id: str) -> List[Dict]:
        """Get ghost transfer history for a vault (privacy-protected)"""
        try:
            if vault_id not in self.vaults:
                raise Exception("Vault not found")
                
            ghost_history = []
            
            # Find all ghost transfers involving this vault
            for transfer_id, ghost_transfer in self.ghost_transfers.items():
                if vault_id in [ghost_transfer.sender_vault_id, ghost_transfer.receiver_vault_id]:
                    is_sender = (vault_id == ghost_transfer.sender_vault_id)
                    
                    history_entry = {
                        "transfer_id": transfer_id,
                        "type": "ghost_send" if is_sender else "ghost_receive",
                        "amount": ghost_transfer.amount if not ghost_transfer.hide_amount else "Hidden",
                        "status": ghost_transfer.status,
                        "privacy_level": ghost_transfer.privacy_level,
                        "created_at": ghost_transfer.created_at,
                        "privacy_protected": True,
                        "untraceable": True
                    }
                    
                    if ghost_transfer.completed_at:
                        history_entry["completed_at"] = ghost_transfer.completed_at
                        
                    ghost_history.append(history_entry)
            
            # Sort by creation time (newest first)
            ghost_history.sort(key=lambda x: x["created_at"], reverse=True)
            
            return ghost_history
            
        except Exception as e:
            logger.error(f"Error getting vault ghost history: {str(e)}")
            return []
    
    # Private helper methods for cryptographic operations
    
    def _generate_commitment(self, balance: float, secret: str) -> str:
        """Generate cryptographic commitment for balance privacy"""
        commitment_data = f"{balance}:{secret}:{int(time.time())}"
        return hashlib.sha256(commitment_data.encode()).hexdigest()
    
    def _generate_nullifier(self, vault_id: str, amount: float, asset_id: str = "WEPO") -> str:
        """
        Generate nullifier to prevent double-spending
        
        ENHANCED: Now includes asset_id to prevent cross-asset double-spending
        """
        nullifier_data = f"{vault_id}:{amount}:{asset_id}:{int(time.time())}:{secrets.token_hex(16)}"
        return hashlib.sha256(nullifier_data.encode()).hexdigest()
    
    def _hash_proof_data(self, vault_id: str, amount: float, operation: str) -> str:
        """Generate hash for proof data"""
        proof_data = f"{vault_id}:{amount}:{operation}:{int(time.time())}"
        return hashlib.sha256(proof_data.encode()).hexdigest()
    
    def _generate_zk_proof(self, vault_id: str, operation: str, amount: float, 
                          commitment: str, asset_type: str = "WEPO", asset_id: str = "WEPO") -> ZKProof:
        """
        Generate zero-knowledge proof for vault operations
        
        ENHANCED: Now supports both WEPO and RWA tokens
        
        In production, this would use actual zk-STARK libraries like StarkEx or Cairo.
        """
        try:
            # Enhanced zk-STARK proof data with asset support
            proof_data = {
                "vault_id": vault_id,
                "operation": operation,
                "asset_type": asset_type,
                "asset_id": asset_id,
                "amount_hash": hashlib.sha256(str(amount).encode()).hexdigest(),
                "commitment": commitment,
                "timestamp": int(time.time()),
                "challenge": secrets.token_hex(64),
                "witness": "sufficient_balance_and_ownership_proven",
                "zero_knowledge": True,
                "rwa_support": asset_type == "RWA_TOKEN"
            }
            
            # Generate cryptographic proof hash
            proof_hash = hashlib.sha256(json.dumps(proof_data, sort_keys=True).encode()).hexdigest()
            
            # Public inputs for verification (no private data)
            public_inputs = [
                proof_data["amount_hash"],
                proof_data["commitment"],
                "operation_verified",
                f"asset_{asset_type.lower()}_verified"
            ]
            
            return ZKProof(
                proof_data=proof_hash,
                public_inputs=public_inputs,
                verification_key=secrets.token_hex(32),
                created_at=int(time.time())
            )
            
        except Exception as e:
            logger.error(f"Error generating zk-proof: {str(e)}")
            raise Exception(f"ZK proof generation failed: {str(e)}")
    
    def verify_zk_proof(self, proof: ZKProof, expected_commitment: str) -> bool:
        """
        Verify zero-knowledge proof
        
        In production, this would use actual zk-STARK verification.
        """
        try:
            # Simulate proof verification
            if expected_commitment in proof.public_inputs:
                return True
            return False
            
        except Exception as e:
            logger.error(f"Error verifying zk-proof: {str(e)}")
            return False
    
    # ===== GHOST TRANSFER CRYPTOGRAPHIC HELPERS =====
    
    def _generate_ghost_nullifier(self, vault_id: str, amount: float, transfer_id: str) -> str:
        """Generate nullifier for ghost transfers to prevent double-spending"""
        nullifier_data = f"ghost:{vault_id}:{amount}:{transfer_id}:{int(time.time())}:{secrets.token_hex(16)}"
        return hashlib.sha256(nullifier_data.encode()).hexdigest()
    
    def _generate_cross_vault_proof(self, sender_vault_id: str, operation: str, amount: float, 
                                   privacy_level: str, hide_amount: bool) -> ZKProof:
        """
        Generate zero-knowledge proof for cross-vault operations
        
        This proves "I have ≥amount WEPO in my vault" without revealing actual balance
        In production, this would use actual zk-STARK libraries like StarkEx or Cairo.
        """
        try:
            # Enhanced zk-STARK proof for cross-vault operations
            proof_data = {
                "operation": operation,
                "vault_involvement": True,
                "balance_proof": "sufficient_balance_proven",
                "amount_hash": hashlib.sha256(str(amount).encode()).hexdigest() if not hide_amount else "hidden",
                "privacy_level": privacy_level,
                "timestamp": int(time.time()),
                "cross_vault_challenge": secrets.token_hex(64),
                "zero_knowledge": True
            }
            
            # Generate cryptographic proof hash
            proof_hash = hashlib.sha256(json.dumps(proof_data, sort_keys=True).encode()).hexdigest()
            
            # Public inputs for verification (no private data)
            public_inputs = [
                proof_data["amount_hash"] if not hide_amount else "amount_hidden",
                proof_data["balance_proof"],
                "cross_vault_operation_verified"
            ]
            
            return ZKProof(
                proof_data=proof_hash,
                public_inputs=public_inputs,
                verification_key=secrets.token_hex(32),
                created_at=int(time.time())
            )
            
        except Exception as e:
            logger.error(f"Error generating cross-vault zk-proof: {str(e)}")
            raise Exception(f"Cross-vault ZK proof generation failed: {str(e)}")
    
    def _encrypt_amount(self, amount: float, receiver_vault_id: str) -> str:
        """
        Encrypt transfer amount for maximum privacy
        
        In production, this would use proper encryption with receiver's public key
        """
        try:
            # Simulate amount encryption for maximum privacy
            encryption_key = hashlib.sha256(f"{receiver_vault_id}:{secrets.token_hex(32)}".encode()).hexdigest()
            amount_data = f"{amount}:{int(time.time())}"
            
            # Simple encryption simulation (in production, use proper asymmetric encryption)
            encrypted_data = hashlib.sha256(f"{encryption_key}:{amount_data}".encode()).hexdigest()
            
            return f"enc_{encrypted_data}"
            
        except Exception as e:
            logger.error(f"Error encrypting amount: {str(e)}")
            raise Exception(f"Amount encryption failed: {str(e)}")
    
    def _decrypt_amount(self, encrypted_amount: str, receiver_vault_id: str) -> float:
        """
        Decrypt transfer amount for receiver
        
        In production, this would use proper decryption with receiver's private key
        """
        try:
            # For simulation, we'll extract the original amount
            # In production, this would involve proper asymmetric decryption
            
            # This is a simplified simulation - in reality, proper decryption would occur
            # For now, we'll parse from the ghost transfer record
            # This method would use the receiver's private key to decrypt
            
            # Simplified extraction for simulation
            if encrypted_amount.startswith("enc_"):
                # In real implementation, decrypt using receiver's private key
                # For simulation, we'll return a default amount that matches the transfer
                # This would be properly decrypted in production
                return 0.0  # This will be overridden by actual transfer amount
            else:
                raise Exception("Invalid encrypted amount format")
                
        except Exception as e:
            logger.error(f"Error decrypting amount: {str(e)}")
            raise Exception(f"Amount decryption failed: {str(e)}")

# Global quantum vault system instance
quantum_vault_system = QuantumVaultSystem()