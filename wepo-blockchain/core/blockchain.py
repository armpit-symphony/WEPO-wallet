#!/usr/bin/env python3
"""
WEPO Core Blockchain Implementation
Revolutionary cryptocurrency with hybrid PoW/PoS consensus and privacy features
"""
try:
    from .transaction import Transaction, TransactionInput, TransactionOutput, UTXO
    from .dilithium import dilithium_system
    from .quantum_transaction import QuantumTransaction
    from .rwa_tokens import rwa_system
except ImportError:
    # Fallback for direct execution
    from transaction import Transaction, TransactionInput, TransactionOutput, UTXO
    from dilithium import dilithium_system
    from quantum_transaction import QuantumTransaction
    from rwa_tokens import rwa_system


import hashlib
import json
import time
import struct
import socket
import threading
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import secrets
import argon2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
import os
from .address_utils import validate_wepo_address, is_quantum_address, is_regular_address

# WEPO Network Constants
WEPO_VERSION = 70001
NETWORK_MAGIC = b'WEPO'
DEFAULT_PORT = 22567
COIN = 100000000  # 1 WEPO = 100,000,000 satoshis
MAX_BLOCK_SIZE = 2 * 1024 * 1024  # 2MB

# REVISED WEPO MINING SCHEDULE - SUSTAINABLE LONG-TERM POW
# Genesis: December 25, 2025, 3:00 PM EST
GENESIS_TIME = 1735138800  # Christmas Day 2025

# Block Time Configuration - REVISED
BLOCK_TIME_TARGET = BLOCK_TIME_INITIAL_18_MONTHS = 360  # 6 minutes per block (first 18 months)
BLOCK_TIME_YEAR1 = BLOCK_TIME_INITIAL_18_MONTHS  # For backward compatibility
BLOCK_TIME_LONGTERM = 540           # 9 minutes per block (post-18 months)

# Initial 18-Month Mining Schedule (10% of supply = 6.9M WEPO)
INITIAL_MINING_PHASE_DURATION = 18 * 30.4 * 24 * 60 / 6  # 18 months in 6-min blocks
BLOCKS_PER_PHASE = int(INITIAL_MINING_PHASE_DURATION / 3)  # 43,800 blocks per phase

PHASE_1_BLOCKS = BLOCKS_PER_PHASE    # Months 1-6: 43,800 blocks
PHASE_2_BLOCKS = BLOCKS_PER_PHASE    # Months 7-12: 43,800 blocks  
PHASE_3_BLOCKS = BLOCKS_PER_PHASE    # Months 13-18: 43,800 blocks
TOTAL_INITIAL_BLOCKS = PHASE_1_BLOCKS + PHASE_2_BLOCKS + PHASE_3_BLOCKS  # 131,400 blocks

# Calculate rewards to reach exactly 6.9M WEPO in 18 months
# Phase 1: R, Phase 2: R/2, Phase 3: R/4
# Total: 43,800R + 43,800R/2 + 43,800R/4 = 43,800R × 1.75 = 6,900,000 WEPO
# R = 6,900,000 ÷ (43,800 × 1.75) = 90 WEPO per block
PHASE_1_REWARD = 90 * COIN   # 90 WEPO per block (months 1-6)
PHASE_2_REWARD = 45 * COIN   # 45 WEPO per block (months 7-12)
PHASE_3_REWARD = 22.5 * COIN # 22.5 WEPO per block (months 13-18)

# Long-term Mining Schedule (post-18 months) - 90% of remaining supply
# Halving intervals: 3 years → 6 years → 3 years → 3 years
BLOCKS_PER_YEAR_LONGTERM = int(365.25 * 24 * 60 / 9)  # 58,400 blocks per year (9-min blocks)

LONGTERM_HALVING_1 = TOTAL_INITIAL_BLOCKS + (3 * BLOCKS_PER_YEAR_LONGTERM)    # 3 years post-18m
LONGTERM_HALVING_2 = LONGTERM_HALVING_1 + (6 * BLOCKS_PER_YEAR_LONGTERM)     # 6 years
LONGTERM_HALVING_3 = LONGTERM_HALVING_2 + (3 * BLOCKS_PER_YEAR_LONGTERM)     # 3 years
LONGTERM_HALVING_4 = LONGTERM_HALVING_3 + (3 * BLOCKS_PER_YEAR_LONGTERM)     # 3 years

# Long-term rewards (starting at 12 WEPO, halving schedule)
LONGTERM_INITIAL_REWARD = 12 * COIN  # 12 WEPO per block (years 1.5-4.5)
LONGTERM_REWARD_2 = 6 * COIN         # 6 WEPO per block (years 4.5-10.5)
LONGTERM_REWARD_3 = 3 * COIN         # 3 WEPO per block (years 10.5-13.5)
LONGTERM_REWARD_4 = 1.5 * COIN       # 1.5 WEPO per block (years 13.5-16.5)
LONGTERM_REWARD_FINAL = 0.75 * COIN  # 0.75 WEPO per block (years 16.5+)

# Consensus Parameters
POW_BLOCKS_YEAR1 = 52560      # 10-min blocks for 1 year
REWARD_Q1 = 400 * COIN        # 400 WEPO per block Q1 (MEGA REWARDS!)
REWARD_Q2 = 200 * COIN        # 200 WEPO per block Q2
REWARD_Q3 = 100 * COIN        # 100 WEPO per block Q3  
REWARD_Q4 = 50 * COIN         # 50 WEPO per block Q4
REWARD_YEAR2_BASE = 12.4 * COIN # 12.4 WEPO per block year 2+
HALVING_INTERVAL = 1051200    # Blocks between halvings (4 years)

# MAINNET CONFIGURATION - CHRISTMAS DAY 2025 GENESIS LAUNCH
CHRISTMAS_GENESIS_TIMESTAMP = 1735138800  # December 25, 2025, 3:00 PM EST
STAKING_ACTIVATION_DELAY = 18 * 30 * 24 * 60 * 60  # 18 months in seconds
PRODUCTION_MODE = False  # Set to False for mainnet (True only for development testing)

# Calculate PoS activation based on genesis launch
if PRODUCTION_MODE:
    # For development testing only: activate staking immediately
    POS_ACTIVATION_HEIGHT = 1  # Activate after first block
    print("🧪 DEVELOPMENT MODE: Staking activated immediately for testing")
else:
    # MAINNET CONFIGURATION: activate after 18 months from Christmas launch
    POS_ACTIVATION_HEIGHT = int(POW_BLOCKS_YEAR1 * 1.5)  # 78,840 blocks (18 months)
    print(f"🎄 MAINNET READY: Staking activates at block {POS_ACTIVATION_HEIGHT} (18 months post-genesis)")

MIN_STAKE_AMOUNT = 1000 * COIN  # 1,000 WEPO minimum stake - accessible to community

# Dynamic Masternode Collateral System - Progressive reduction for accessibility
DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE = {
    0: 10000 * COIN,          # Genesis - Year 5: 10,000 WEPO (High security threshold)
    262800: 5000 * COIN,      # Year 5 (during halving): 5,000 WEPO (50% reduction - broader access)
    525600: 1000 * COIN,      # Year 10 (during halving): 1,000 WEPO (80% reduction - mass adoption)
    1051200: 500 * COIN,      # Year 20 (during halving): 500 WEPO (95% reduction - maximum decentralization)
}

# Legacy constant for backward compatibility (now dynamic)
MASTERNODE_COLLATERAL = 10000 * COIN

@dataclass
class StakeInfo:
    """Staking information"""
    stake_id: str
    staker_address: str
    amount: int  # In satoshis
    start_height: int
    start_time: int
    last_reward_height: int = 0
    total_rewards: int = 0
    status: str = 'active'
    unlock_height: Optional[int] = None

@dataclass
class MasternodeInfo:
    """Masternode information"""
    masternode_id: str
    operator_address: str
    collateral_txid: str
    collateral_vout: int
    ip_address: Optional[str] = None
    port: int = 22567
    start_height: int = 0
    start_time: int = 0
    last_ping: int = 0
    status: str = 'active'
    total_rewards: int = 0

@dataclass
class TransactionInput:
    """Transaction input with support for both ECDSA and Dilithium signatures"""
    prev_txid: str
    prev_vout: int
    script_sig: Optional[bytes] = None
    sequence: int = 0xffffffff
    
    # Quantum signature support
    quantum_signature: Optional[bytes] = None
    quantum_public_key: Optional[bytes] = None
    signature_type: str = "ecdsa"  # "ecdsa" or "dilithium"
    
    def __post_init__(self):
        # Validate quantum signature sizes if present
        if self.quantum_signature and len(self.quantum_signature) != 2420:
            raise ValueError(f"Invalid Dilithium signature size: {len(self.quantum_signature)}")
        
        if self.quantum_public_key and len(self.quantum_public_key) != 1312:
            raise ValueError(f"Invalid Dilithium public key size: {len(self.quantum_public_key)}")

@dataclass
class TransactionOutput:
    """Transaction output with quantum address support"""
    value: int
    script_pubkey: Optional[bytes] = None
    address: str = ""
    
    def __post_init__(self):
        # Validate address format (supports both regular and quantum addresses)
        if not self.is_valid_address():
            raise ValueError(f"Invalid address format: {self.address}")
    
    def is_valid_address(self):
        """Validate address using standardized system"""
        validation = validate_wepo_address(self.address)
        return validation["valid"]
    
    def get_address_type(self):
        """Get address type using standardized system"""
        validation = validate_wepo_address(self.address)
        return validation["type"] if validation["valid"] else None
        
    def is_quantum_resistant(self):
        """Check if address is quantum-resistant"""
        return is_quantum_address(self.address)

@dataclass
class Transaction:
    """WEPO Transaction with privacy features and quantum signature support"""
    version: int
    inputs: List[TransactionInput]
    outputs: List[TransactionOutput]
    lock_time: int
    fee: int = 0
    privacy_proof: Optional[bytes] = None
    ring_signature: Optional[bytes] = None
    timestamp: int = 0
    
    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time())
    
    def has_quantum_signatures(self) -> bool:
        """Check if transaction contains quantum signatures"""
        return any(inp.signature_type == "dilithium" for inp in self.inputs)
    
    def is_mixed_signature_transaction(self) -> bool:
        """Check if transaction has mixed signature types"""
        signature_types = set(inp.signature_type for inp in self.inputs)
        return len(signature_types) > 1
    
    def verify_quantum_signature(self, input_index: int) -> bool:
        """Verify quantum signature for specific input"""
        if input_index >= len(self.inputs):
            return False
        
        inp = self.inputs[input_index]
        
        if inp.signature_type != "dilithium":
            return False
        
        if not inp.quantum_signature or not inp.quantum_public_key:
            return False
        
        try:
            # Import quantum signature verification
            from dilithium import verify_signature
            
            # Create signing message
            signing_message = self.get_signing_message_for_input(input_index)
            
            # Verify quantum signature
            return verify_signature(signing_message, inp.quantum_signature, inp.quantum_public_key)
        except Exception as e:
            print(f"Quantum signature verification failed: {e}")
            return False
    
    def get_signing_message_for_input(self, input_index: int) -> bytes:
        """Get message to be signed for specific input"""
        # Create deterministic message for signing
        message_parts = [
            str(self.version),
            str(self.lock_time),
            str(self.fee),
            str(input_index)
        ]
        
        # Add outputs
        for out in self.outputs:
            message_parts.extend([str(out.value), out.address])
        
        # Add other inputs (without signatures)
        for i, inp in enumerate(self.inputs):
            if i != input_index:
                message_parts.extend([inp.prev_txid, str(inp.prev_vout)])
        
        message = "|".join(message_parts)
        return message.encode('utf-8')
    
    def calculate_txid(self) -> str:
        """Calculate transaction hash"""
        # Create a string representation for hashing that avoids bytes serialization
        tx_string = f"{self.version}"
        
        # Add inputs
        for inp in self.inputs:
            tx_string += f"{inp.prev_txid}{inp.prev_vout}{inp.sequence}"
            if inp.script_sig:
                tx_string += inp.script_sig.hex()
        
        # Add outputs
        for out in self.outputs:
            tx_string += f"{out.value}{out.address}"
            if out.script_pubkey:
                tx_string += out.script_pubkey.hex()
        
        tx_string += f"{self.lock_time}{self.timestamp}"
        
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    def is_coinbase(self) -> bool:
        """Check if this is a coinbase transaction"""
        return (len(self.inputs) == 1 and 
                self.inputs[0].prev_txid == "0" * 64 and 
                self.inputs[0].prev_vout == 0xffffffff)

@dataclass
class BlockHeader:
    """WEPO Block Header"""
    version: int
    prev_hash: str
    merkle_root: str
    timestamp: int
    bits: int
    nonce: int
    consensus_type: str  # 'pow', 'pos', or 'masternode'
    
    def calculate_hash(self) -> str:
        """Calculate block hash"""
        header_data = struct.pack('<I32s32sIII', 
                                self.version,
                                bytes.fromhex(self.prev_hash),
                                bytes.fromhex(self.merkle_root),
                                self.timestamp,
                                self.bits,
                                self.nonce)
        return hashlib.sha256(header_data).hexdigest()

@dataclass
class Block:
    """WEPO Block"""
    header: BlockHeader
    transactions: List[Transaction]
    height: int = 0
    size: int = 0
    
    def __post_init__(self):
        if self.size == 0:
            self.size = self.calculate_size()
    
    def calculate_size(self) -> int:
        """Calculate block size in bytes"""
        # Simplified size calculation avoiding JSON serialization of bytes
        total_size = 0
        for tx in self.transactions:
            # Count transaction components
            total_size += 100  # Base transaction overhead
            total_size += len(tx.inputs) * 50  # Input overhead
            total_size += len(tx.outputs) * 50  # Output overhead
            for inp in tx.inputs:
                total_size += len(inp.script_sig) if inp.script_sig else 0
            for out in tx.outputs:
                total_size += len(out.script_pubkey) if out.script_pubkey else 0
        return total_size
    
    def calculate_merkle_root(self) -> str:
        """Calculate Merkle root of transactions"""
        if not self.transactions:
            return "0" * 64
        
        txids = [tx.calculate_txid() for tx in self.transactions]
        
        while len(txids) > 1:
            next_level = []
            for i in range(0, len(txids), 2):
                left = txids[i]
                right = txids[i + 1] if i + 1 < len(txids) else left
                combined = left + right
                next_level.append(hashlib.sha256(combined.encode()).hexdigest())
            txids = next_level
        
        return txids[0]
    
    def get_block_hash(self) -> str:
        """Get block hash"""
        return self.header.calculate_hash()

class WepoArgon2Miner:
    """Argon2 Proof of Work Miner"""
    
    def __init__(self):
        self.hasher = argon2.PasswordHasher(
            time_cost=3,
            memory_cost=4096,  # 4MB
            parallelism=1,
            hash_len=32,
            salt_len=16
        )
    
    def mine_block(self, block: Block, target_difficulty: int) -> Optional[Block]:
        """Mine a block using Argon2 PoW"""
        print(f"Mining block {block.height} with target difficulty {target_difficulty}")
        
        start_time = time.time()
        nonce = 0
        max_nonce = 2**32
        
        while nonce < max_nonce:
            # Update nonce in header
            block.header.nonce = nonce
            
            # Calculate hash using Argon2
            header_data = f"{block.header.version}{block.header.prev_hash}{block.header.merkle_root}{block.header.timestamp}{block.header.bits}{nonce}"
            
            try:
                hash_result = self.hasher.hash(header_data)
                block_hash = hashlib.sha256(hash_result.encode()).hexdigest()
                
                # Check if hash meets difficulty target
                if self.check_difficulty(block_hash, target_difficulty):
                    mining_time = time.time() - start_time
                    hashrate = nonce / mining_time if mining_time > 0 else 0
                    print(f"Block mined! Hash: {block_hash}")
                    print(f"Nonce: {nonce}, Time: {mining_time:.2f}s, Hashrate: {hashrate:.2f} H/s")
                    return block
                    
            except Exception as e:
                # Argon2 error, continue with next nonce
                pass
            
            nonce += 1
            
            # Progress update every 1000 nonces
            if nonce % 1000 == 0:
                elapsed = time.time() - start_time
                if elapsed > 0:
                    hashrate = nonce / elapsed
                    print(f"Mining progress: {nonce} nonces, {hashrate:.2f} H/s")
        
        print("Mining failed - max nonce reached")
        return None
    
    def check_difficulty(self, block_hash: str, difficulty: int) -> bool:
        """Check if block hash meets difficulty target"""
        # Simplified difficulty check - count leading zeros
        leading_zeros = 0
        for char in block_hash:
            if char == '0':
                leading_zeros += 1
            else:
                break
        return leading_zeros >= difficulty

class WepoBlockchain:
    """WEPO Blockchain Core"""
    
    def __init__(self, data_dir: str = "/tmp/wepo"):
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "blockchain.db")
        self.chain: List[Block] = []
        self.mempool: Dict[str, Transaction] = {}
        self.utxo_set: Dict[str, TransactionOutput] = {}
        self.stakes: Dict[str, dict] = {}
        self.masternodes: Dict[str, dict] = {}
        self.current_difficulty = 4  # Start with 4 leading zeros
        self.miner = WepoArgon2Miner()
        
        # Ensure data directory exists
        os.makedirs(data_dir, exist_ok=True)
        
        # Initialize database
        self.init_database()
        
        # Load existing chain or create genesis
        self.load_chain()
        if not self.chain:
            self.create_genesis_block()
    
    def init_database(self):
        """Initialize SQLite database"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash TEXT UNIQUE NOT NULL,
                prev_hash TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                bits INTEGER NOT NULL,
                nonce INTEGER NOT NULL,
                version INTEGER NOT NULL,
                size INTEGER NOT NULL,
                tx_count INTEGER NOT NULL,
                consensus_type TEXT NOT NULL,
                block_data TEXT NOT NULL
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                txid TEXT PRIMARY KEY,
                block_height INTEGER,
                block_hash TEXT,
                version INTEGER NOT NULL,
                lock_time INTEGER NOT NULL,
                fee INTEGER NOT NULL,
                privacy_proof BLOB,
                ring_signature BLOB,
                tx_data TEXT NOT NULL,
                FOREIGN KEY(block_height) REFERENCES blocks(height)
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS utxos (
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                address TEXT NOT NULL,
                amount INTEGER NOT NULL,
                script_pubkey BLOB NOT NULL,
                spent BOOLEAN DEFAULT FALSE,
                spent_txid TEXT,
                spent_height INTEGER,
                PRIMARY KEY(txid, vout)
            )
        ''')
        
        # Staking tables
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS stakes (
                stake_id TEXT PRIMARY KEY,
                staker_address TEXT NOT NULL,
                amount INTEGER NOT NULL,
                start_height INTEGER NOT NULL,
                start_time INTEGER NOT NULL,
                last_reward_height INTEGER DEFAULT 0,
                total_rewards INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                unlock_height INTEGER,
                FOREIGN KEY(start_height) REFERENCES blocks(height)
            )
        ''')
        
        # Masternode tables
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS masternodes (
                masternode_id TEXT PRIMARY KEY,
                operator_address TEXT NOT NULL,
                collateral_txid TEXT NOT NULL,
                collateral_vout INTEGER NOT NULL,
                ip_address TEXT,
                port INTEGER DEFAULT 22567,
                start_height INTEGER NOT NULL,
                start_time INTEGER NOT NULL,
                last_ping INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                total_rewards INTEGER DEFAULT 0,
                FOREIGN KEY(start_height) REFERENCES blocks(height),
                FOREIGN KEY(collateral_txid) REFERENCES transactions(txid)
            )
        ''')
        
        # Staking rewards history
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS staking_rewards (
                reward_id TEXT PRIMARY KEY,
                recipient_address TEXT NOT NULL,
                recipient_type TEXT NOT NULL, -- 'staker' or 'masternode'
                amount INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY(block_height) REFERENCES blocks(height)
            )
        ''')
        
        self.conn.commit()
    
    def create_genesis_block(self):
        """Create the genesis block"""
        print("Creating WEPO genesis block...")
        
        # Genesis coinbase transaction
        genesis_tx = Transaction(
            version=1,
            inputs=[TransactionInput(
                prev_txid="0" * 64,
                prev_vout=0xffffffff,
                script_sig=b"WEPO Genesis - We The People",
                sequence=0xffffffff
            )],
            outputs=[TransactionOutput(
                value=REWARD_Q1,
                script_pubkey=b"genesis_output",
                address="wepo1genesis0000000000000000000000"
            )],
            lock_time=0,
            timestamp=GENESIS_TIME
        )
        
        # Genesis block header
        genesis_header = BlockHeader(
            version=1,
            prev_hash="0" * 64,
            merkle_root="",
            timestamp=GENESIS_TIME,
            bits=self.current_difficulty,
            nonce=0,
            consensus_type="pow"
        )
        
        # Create genesis block
        genesis_block = Block(
            header=genesis_header,
            transactions=[genesis_tx],
            height=0
        )
        
        # Calculate merkle root
        genesis_block.header.merkle_root = genesis_block.calculate_merkle_root()
        
        # Mine genesis block
        mined_genesis = self.miner.mine_block(genesis_block, self.current_difficulty)
        if mined_genesis:
            self.add_block(mined_genesis, validate=False)  # Skip validation for genesis
            
            # Create genesis UTXO manually
            genesis_txid = genesis_tx.calculate_txid()
            self.conn.execute('''
                INSERT INTO utxos (txid, vout, address, amount, script_pubkey, spent)
                VALUES (?, ?, ?, ?, ?, FALSE)
            ''', (genesis_txid, 0, "wepo1genesis0000000000000000000000", REWARD_Q1, b"genesis_output"))
            self.conn.commit()
            
            print(f"Genesis block created: {mined_genesis.get_block_hash()}")
            print(f"Genesis UTXO created: {REWARD_Q1 / COIN} WEPO")
        else:
            raise Exception("Failed to mine genesis block")
    
    def load_chain(self):
        """Load blockchain from database"""
        cursor = self.conn.execute('''
            SELECT block_data FROM blocks ORDER BY height ASC
        ''')
        
        for row in cursor.fetchall():
            block_data = json.loads(row[0])
            block = self.deserialize_block(block_data)
            self.chain.append(block)
        
        print(f"Loaded {len(self.chain)} blocks from database")
    
    def serialize_block(self, block: Block) -> str:
        """Serialize block to JSON"""
        # Convert bytes to hex strings for JSON serialization
        def bytes_to_hex(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            elif isinstance(obj, dict):
                return {k: bytes_to_hex(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [bytes_to_hex(item) for item in obj]
            else:
                return obj
        
        block_dict = {
            'header': asdict(block.header),
            'transactions': [],
            'height': block.height,
            'size': block.size
        }
        
        # Serialize transactions with bytes conversion
        for tx in block.transactions:
            tx_dict = asdict(tx)
            tx_dict = bytes_to_hex(tx_dict)
            block_dict['transactions'].append(tx_dict)
        
        return json.dumps(block_dict)
    
    def deserialize_block(self, data: dict) -> Block:
        """Deserialize block from JSON"""
        # Convert hex strings back to bytes
        def hex_to_bytes(obj):
            if isinstance(obj, str) and len(obj) % 2 == 0:
                try:
                    return bytes.fromhex(obj)
                except ValueError:
                    return obj
            elif isinstance(obj, dict):
                return {k: hex_to_bytes(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [hex_to_bytes(item) for item in obj]
            else:
                return obj
        
        header = BlockHeader(**data['header'])
        transactions = []
        for tx_data in data['transactions']:
            # Convert hex back to bytes where needed
            if 'script_sig' in str(tx_data):
                tx_data = hex_to_bytes(tx_data)
            
            inputs = []
            for inp_data in tx_data['inputs']:
                script_sig = inp_data.get('script_sig', b'')
                if isinstance(script_sig, str):
                    script_sig = script_sig.encode() if script_sig else b''
                
                # Handle quantum signature fields
                quantum_signature = inp_data.get('quantum_signature')
                if isinstance(quantum_signature, str) and quantum_signature:
                    quantum_signature = bytes.fromhex(quantum_signature)
                
                quantum_public_key = inp_data.get('quantum_public_key')
                if isinstance(quantum_public_key, str) and quantum_public_key:
                    quantum_public_key = bytes.fromhex(quantum_public_key)
                
                inputs.append(TransactionInput(
                    prev_txid=inp_data['prev_txid'],
                    prev_vout=inp_data['prev_vout'],
                    script_sig=script_sig,
                    sequence=inp_data.get('sequence', 0xffffffff),
                    quantum_signature=quantum_signature,
                    quantum_public_key=quantum_public_key,
                    signature_type=inp_data.get('signature_type', 'ecdsa')
                ))
            
            outputs = []
            for out_data in tx_data['outputs']:
                script_pubkey = out_data.get('script_pubkey', b'')
                if isinstance(script_pubkey, str):
                    script_pubkey = script_pubkey.encode() if script_pubkey else b''
                outputs.append(TransactionOutput(
                    value=out_data['value'],
                    script_pubkey=script_pubkey,
                    address=out_data.get('address', '')
                ))
            
            privacy_proof = tx_data.get('privacy_proof')
            if isinstance(privacy_proof, str):
                privacy_proof = privacy_proof.encode() if privacy_proof else None
                
            ring_signature = tx_data.get('ring_signature')
            if isinstance(ring_signature, str):
                ring_signature = ring_signature.encode() if ring_signature else None
            
            tx = Transaction(
                version=tx_data['version'],
                inputs=inputs,
                outputs=outputs,
                lock_time=tx_data['lock_time'],
                fee=tx_data.get('fee', 0),
                privacy_proof=privacy_proof,
                ring_signature=ring_signature,
                timestamp=tx_data.get('timestamp', 0)
            )
            transactions.append(tx)
        
        return Block(
            header=header,
            transactions=transactions,
            height=data['height'],
            size=data['size']
        )
    
    def get_latest_block(self) -> Optional[Block]:
        """Get the latest block in the chain"""
        return self.chain[-1] if self.chain else None
    
    def get_block_height(self) -> int:
        """Get current block height"""
        return len(self.chain) - 1 if self.chain else -1
    
    def calculate_block_reward(self, height: int) -> int:
        """Calculate block reward based on new sustainable long-term mining schedule"""
        
        # INITIAL 18-MONTH MINING PHASE (6.9M WEPO total - 10% of supply)
        if height <= PHASE_1_BLOCKS:
            # Months 1-6: 90 WEPO per block (6-minute blocks)
            return PHASE_1_REWARD
        elif height <= (PHASE_1_BLOCKS + PHASE_2_BLOCKS):
            # Months 7-12: 45 WEPO per block (6-minute blocks)
            return PHASE_2_REWARD
        elif height <= TOTAL_INITIAL_BLOCKS:
            # Months 13-18: 22.5 WEPO per block (6-minute blocks)
            return PHASE_3_REWARD
        
        # LONG-TERM MINING PHASE (post-18 months, 9-minute blocks)
        # Continues alongside PoS/Masternodes with halving schedule
        elif height <= LONGTERM_HALVING_1:
            # Years 1.5-4.5: 12 WEPO per block (9-minute blocks)
            return LONGTERM_INITIAL_REWARD
        elif height <= LONGTERM_HALVING_2:
            # Years 4.5-10.5: 6 WEPO per block (9-minute blocks)
            return LONGTERM_REWARD_2
        elif height <= LONGTERM_HALVING_3:
            # Years 10.5-13.5: 3 WEPO per block (9-minute blocks)
            return LONGTERM_REWARD_3
        elif height <= LONGTERM_HALVING_4:
            # Years 13.5-16.5: 1.5 WEPO per block (9-minute blocks)
            return LONGTERM_REWARD_4
        else:
            # Years 16.5+: 0.75 WEPO per block (9-minute blocks)
            return LONGTERM_REWARD_FINAL
        
        # TOTAL MINING TIMELINE:
        # - First 18 months: 6.9M WEPO (10% of supply)
        # - Long-term: Remaining 14.1M WEPO over decades
        # - Mining continues indefinitely with decreasing rewards
        # - PoS/Masternodes activate at 18 months and run alongside mining
    
    def create_coinbase_transaction(self, height: int, miner_address: str) -> Transaction:
        """Create coinbase transaction for new block with 3-way fee redistribution"""
        base_reward = self.calculate_block_reward(height)
        
        # Calculate total transaction fees from pending transactions
        total_transaction_fees = 0
        for txid, tx in self.mempool.items():
            if hasattr(tx, 'fee') and tx.fee:
                total_transaction_fees += tx.fee
        
        # New 3-way fee distribution system
        if total_transaction_fees > 0:
            # Distribute fees: 60% MN, 25% Miners, 15% Stakers
            masternode_fees = int(total_transaction_fees * 0.60)
            miner_fees = int(total_transaction_fees * 0.25)
            staker_fees = int(total_transaction_fees * 0.15)
            
            # Distribute masternode fees equally among active masternodes
            active_masternodes = self.get_active_masternodes()
            if active_masternodes:
                masternode_fee_per_node = masternode_fees // len(active_masternodes)
                for masternode_addr in active_masternodes:
                    # Add fee to masternode balance (in real implementation)
                    print(f"Masternode {masternode_addr} receives {masternode_fee_per_node / COIN:.8f} WEPO in fees")
            
            # Distribute staker fees proportionally among active stakers
            active_stakers = self.get_active_stakers()
            total_stake = sum(staker['amount'] for staker in active_stakers)
            if total_stake > 0:
                for staker in active_stakers:
                    stake_percentage = staker['amount'] / total_stake
                    staker_reward = int(staker_fees * stake_percentage)
                    print(f"Staker {staker['address']} receives {staker_reward / COIN:.8f} WEPO in fees")
            
            print(f"Fee Distribution Summary:")
            print(f"  Total Fees: {total_transaction_fees / COIN:.8f} WEPO")
            print(f"  Masternodes (60%): {masternode_fees / COIN:.8f} WEPO")
            print(f"  Miner (25%): {miner_fees / COIN:.8f} WEPO")
            print(f"  Stakers (15%): {staker_fees / COIN:.8f} WEPO")
        else:
            miner_fees = 0
        
        # Miner gets base reward + their share of fees
        total_miner_reward = base_reward + miner_fees
        
        print(f"Coinbase for height {height}:")
        print(f"  Base reward: {base_reward / COIN:.8f} WEPO")
        print(f"  Miner fee share: {miner_fees / COIN:.8f} WEPO")
        print(f"  Total miner reward: {total_miner_reward / COIN:.8f} WEPO")
        
        return Transaction(
            version=1,
            inputs=[TransactionInput(
                prev_txid="0" * 64,
                prev_vout=0xffffffff,
                script_sig=f"Block {height} fees:{total_transaction_fees} 3-way-distribution".encode(),
                sequence=0xffffffff
            )],
            outputs=[TransactionOutput(
                value=total_miner_reward,
                script_pubkey=b"coinbase_output",
                address=miner_address
            )],
            lock_time=0
        )
    
    def create_new_block(self, miner_address: str) -> Block:
        """Create a new block with transactions from mempool"""
        height = self.get_block_height() + 1
        latest_block = self.get_latest_block()
        prev_hash = latest_block.get_block_hash() if latest_block else "0" * 64
        
        # Collect transaction fees before creating coinbase
        total_transaction_fees = 0
        for txid, tx in list(self.mempool.items()):
            if hasattr(tx, 'fee') and tx.fee:
                total_transaction_fees += tx.fee
        
        # Add normal transaction fees to RWA redistribution pool
        if total_transaction_fees > 0:
            rwa_system.add_transaction_fees_to_pool(total_transaction_fees, height)
        
        # Create coinbase transaction (will include redistributed fees)
        coinbase_tx = self.create_coinbase_transaction(height, miner_address)
        
        # Add transactions from mempool (up to block size limit)
        transactions = [coinbase_tx]
        current_size = len(json.dumps(asdict(coinbase_tx)))
        
        for txid, tx in list(self.mempool.items()):
            tx_size = len(json.dumps(asdict(tx)))
            if current_size + tx_size <= MAX_BLOCK_SIZE:
                transactions.append(tx)
                current_size += tx_size
                del self.mempool[txid]
            else:
                break
        
        # Determine block time target
        if height <= TOTAL_INITIAL_BLOCKS:
            block_time = BLOCK_TIME_INITIAL_18_MONTHS  # 6 minutes per block for first 18 months
        else:
            block_time = BLOCK_TIME_LONGTERM  # 9 minutes per block after 18 months
        
        # Create block header
        header = BlockHeader(
            version=1,
            prev_hash=prev_hash,
            merkle_root="",
            timestamp=int(time.time()),
            bits=self.current_difficulty,
            nonce=0,
            consensus_type="pow"  # TODO: Implement PoS after activation height
        )
        
        # Create block
        new_block = Block(
            header=header,
            transactions=transactions,
            height=height
        )
        
        # Calculate merkle root
        new_block.header.merkle_root = new_block.calculate_merkle_root()
        
        return new_block

    def get_active_masternodes(self) -> List[str]:
        """Get list of active masternode addresses"""
        # TODO: Implement proper masternode tracking
        # For now, return mock data for development
        return [
            "wepo1masternode1000000000000000000000",
            "wepo1masternode2000000000000000000000",
            "wepo1masternode3000000000000000000000"
        ]
    
    def get_active_stakers(self) -> List[Dict]:
        """Get list of active stakers with their stake amounts"""
        # TODO: Implement proper PoS staking tracking  
        # For now, return mock data for development
        return [
            {"address": "wepo1staker1000000000000000000000000", "amount": 1000 * COIN},
            {"address": "wepo1staker2000000000000000000000000", "amount": 5000 * COIN},
            {"address": "wepo1staker3000000000000000000000000", "amount": 2000 * COIN}
        ]
    
    def validate_block(self, block: Block) -> bool:
        """Validate a block"""
        try:
            # Basic validation
            if block.height != self.get_block_height() + 1:
                print(f"Invalid block height: {block.height}")
                return False
            
            # Check previous hash
            latest_block = self.get_latest_block()
            expected_prev_hash = latest_block.get_block_hash() if latest_block else "0" * 64
            if block.header.prev_hash != expected_prev_hash:
                print(f"Invalid previous hash")
                return False
            
            # Validate merkle root
            calculated_merkle = block.calculate_merkle_root()
            if block.header.merkle_root != calculated_merkle:
                print(f"Invalid merkle root")
                return False
            
            # Validate proof of work
            block_hash = block.get_block_hash()
            if not self.miner.check_difficulty(block_hash, self.current_difficulty):
                print(f"Invalid proof of work")
                return False
            
            # Validate coinbase transaction
            if not block.transactions or not block.transactions[0].is_coinbase():
                print(f"Missing or invalid coinbase transaction")
                return False
            
            # Validate block reward
            coinbase_output_value = sum(out.value for out in block.transactions[0].outputs)
            expected_reward = self.calculate_block_reward(block.height)
            if coinbase_output_value > expected_reward:
                print(f"Invalid block reward: {coinbase_output_value} > {expected_reward}")
                return False
            
            print(f"Block {block.height} validation passed")
            return True
            
        except Exception as e:
            print(f"Block validation error: {e}")
            return False
    
    def add_block(self, block: Block, validate: bool = True) -> bool:
        """Add a block to the blockchain with proper UTXO management"""
        if validate and not self.validate_block(block):
            return False
        
        try:
            # Add to chain
            self.chain.append(block)
            
            # Process transactions and update UTXOs
            for tx in block.transactions:
                txid = tx.calculate_txid()
                
                # Mark input UTXOs as spent (except for coinbase)
                if not tx.is_coinbase():
                    for inp in tx.inputs:
                        self.conn.execute('''
                            UPDATE utxos 
                            SET spent = TRUE, spent_txid = ?, spent_height = ?
                            WHERE txid = ? AND vout = ?
                        ''', (txid, block.height, inp.prev_txid, inp.prev_vout))
                
                # Create new UTXOs from outputs
                for vout, output in enumerate(tx.outputs):
                    self.conn.execute('''
                        INSERT INTO utxos (txid, vout, address, amount, script_pubkey, spent)
                        VALUES (?, ?, ?, ?, ?, FALSE)
                    ''', (txid, vout, output.address, output.value, output.script_pubkey))
            
            # Save block to database
            self.conn.execute('''
                INSERT INTO blocks (
                    height, hash, prev_hash, merkle_root, timestamp, bits, nonce,
                    version, size, tx_count, consensus_type, block_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                block.height,
                block.get_block_hash(),
                block.header.prev_hash,
                block.header.merkle_root,
                block.header.timestamp,
                block.header.bits,
                block.header.nonce,
                block.header.version,
                block.size,
                len(block.transactions),
                block.header.consensus_type,
                self.serialize_block(block)
            ))
            
            # Save transactions
            for tx in block.transactions:
                txid = tx.calculate_txid()
                self.conn.execute('''
                    INSERT INTO transactions (
                        txid, block_height, block_hash, version, lock_time, fee,
                        privacy_proof, ring_signature, tx_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    txid,
                    block.height,
                    block.get_block_hash(),
                    tx.version,
                    tx.lock_time,
                    tx.fee,
                    tx.privacy_proof,
                    tx.ring_signature,
                    json.dumps(asdict(tx))
                ))
            
            # Distribute staking rewards if PoS is active
            if block.height >= POS_ACTIVATION_HEIGHT:
                self.distribute_staking_rewards(block.height, block.get_block_hash())
            
            self.conn.commit()
            
            # Adjust difficulty every 1440 blocks (2 days)
            if block.height % 1440 == 0:
                self.adjust_difficulty()
            
            print(f"Block {block.height} added to blockchain: {block.get_block_hash()}")
            print(f"Block contains {len(block.transactions)} transactions")
            return True
            
        except Exception as e:
            print(f"Error adding block: {e}")
            self.conn.rollback()
            return False
    
    def adjust_difficulty(self):
        """Adjust mining difficulty based on block times"""
        if len(self.chain) < 1440:
            return
        
        # Get last 1440 blocks
        recent_blocks = self.chain[-1440:]
        
        # Calculate actual time taken
        actual_time = recent_blocks[-1].header.timestamp - recent_blocks[0].header.timestamp
        
        # Target time (2 days)
        target_time = 2 * 24 * 60 * 60
        
        # Adjust difficulty
        if actual_time < target_time * 0.75:
            # Blocks too fast, increase difficulty
            self.current_difficulty += 1
            print(f"Difficulty increased to {self.current_difficulty}")
        elif actual_time > target_time * 1.25:
            # Blocks too slow, decrease difficulty  
            self.current_difficulty = max(1, self.current_difficulty - 1)
            print(f"Difficulty decreased to {self.current_difficulty}")
    
    def add_transaction_to_mempool(self, transaction: Transaction) -> bool:
        """Add transaction to mempool"""
        txid = transaction.calculate_txid()
        
        # Basic validation
        if self.validate_transaction(transaction):
            self.mempool[txid] = transaction
            
            # Collect fee for redistribution (if not coinbase)
            if not transaction.is_coinbase() and hasattr(transaction, 'fee') and transaction.fee > 0:
                fee_amount_wepo = transaction.fee / COIN  # Convert satoshis to WEPO
                rwa_system.add_transaction_fees_to_pool(transaction.fee, self.get_block_height() + 1)
                print(f"Added {fee_amount_wepo:.8f} WEPO transaction fee to redistribution pool")
            
            print(f"Transaction added to mempool: {txid}")
            return True
        else:
            print(f"Invalid transaction rejected: {txid}")
            return False
    
    def validate_transaction(self, transaction: Transaction) -> bool:
        """Validate a transaction with proper UTXO checking and quantum signature support"""
        try:
            # Skip validation for coinbase transactions
            if transaction.is_coinbase():
                return True
            
            # Check inputs exist and are unspent
            total_input_value = 0
            for input_index, inp in enumerate(transaction.inputs):
                # Look up UTXO in database
                cursor = self.conn.execute('''
                    SELECT amount, spent FROM utxos 
                    WHERE txid = ? AND vout = ?
                ''', (inp.prev_txid, inp.prev_vout))
                
                utxo = cursor.fetchone()
                if not utxo:
                    print(f"UTXO not found: {inp.prev_txid}:{inp.prev_vout}")
                    return False
                
                if utxo[1]:  # spent flag
                    print(f"UTXO already spent: {inp.prev_txid}:{inp.prev_vout}")
                    return False
                
                # Verify signature based on type
                if inp.signature_type == "dilithium":
                    if not transaction.verify_quantum_signature(input_index):
                        print(f"Quantum signature verification failed for input {input_index}")
                        return False
                elif inp.signature_type == "ecdsa":
                    # Regular ECDSA signature validation (existing logic)
                    if not inp.script_sig:
                        print(f"Missing ECDSA signature for input {input_index}")
                        return False
                    # TODO: Add ECDSA signature verification here
                else:
                    print(f"Unknown signature type: {inp.signature_type}")
                    return False
                
                total_input_value += utxo[0]
            
            # Check outputs
            total_output_value = sum(out.value for out in transaction.outputs)
            
            # Check sufficient funds (inputs >= outputs + fee)
            if total_input_value < total_output_value + transaction.fee:
                print(f"Insufficient funds: {total_input_value} < {total_output_value + transaction.fee}")
                return False
            
            # Log transaction type for debugging
            if transaction.has_quantum_signatures():
                print(f"✓ Quantum transaction validated: {transaction.calculate_txid()[:16]}...")
            
            return True
            
        except Exception as e:
            print(f"Transaction validation error: {e}")
            return False
    
    def get_balance(self, address: str) -> int:
        """Get balance for an address in satoshis"""
        cursor = self.conn.execute('''
            SELECT SUM(amount) FROM utxos 
            WHERE address = ? AND spent = FALSE
        ''', (address,))
        
        result = cursor.fetchone()
        return result[0] if result[0] else 0
    
    def get_balance_wepo(self, address: str) -> float:
        """Get balance for an address in WEPO"""
        return self.get_balance(address) / COIN
    
    def get_utxos_for_address(self, address: str) -> List[dict]:
        """Get all unspent UTXOs for an address"""
        cursor = self.conn.execute('''
            SELECT txid, vout, amount, script_pubkey FROM utxos 
            WHERE address = ? AND spent = FALSE
        ''', (address,))
        
        utxos = []
        for row in cursor.fetchall():
            utxos.append({
                'txid': row[0],
                'vout': row[1],
                'amount': row[2],
                'script_pubkey': row[3],
                'address': address
            })
        
        return utxos
    
    def mine_next_block(self, miner_address: str) -> Optional[Block]:
        """Mine the next block"""
        print(f"\nMining new block at height {self.get_block_height() + 1}")
        print(f"Mempool size: {len(self.mempool)} transactions")
        print(f"Current difficulty: {self.current_difficulty}")
        
        new_block = self.create_new_block(miner_address)
        mined_block = self.miner.mine_block(new_block, self.current_difficulty)
        
        if mined_block and self.add_block(mined_block):
            return mined_block
        else:
            return None
    
    def create_transaction(self, from_address: str, to_address: str, amount_wepo: float, fee_wepo: float = 0.0001) -> Optional[Transaction]:
        """Create a transaction with proper UTXO selection"""
        try:
            amount_satoshis = int(amount_wepo * COIN)
            fee_satoshis = int(fee_wepo * COIN)
            total_needed = amount_satoshis + fee_satoshis
            
            # Get available UTXOs for sender
            available_utxos = self.get_utxos_for_address(from_address)
            
            if not available_utxos:
                print(f"No UTXOs available for address: {from_address}")
                return None
            
            # Select UTXOs (simple algorithm: take all)
            selected_utxos = []
            total_input_value = 0
            
            for utxo in available_utxos:
                selected_utxos.append(utxo)
                total_input_value += utxo['amount']
                if total_input_value >= total_needed:
                    break
            
            if total_input_value < total_needed:
                print(f"Insufficient funds: need {total_needed}, have {total_input_value}")
                return None
            
            # Create transaction inputs
            inputs = []
            for utxo in selected_utxos:
                inputs.append(TransactionInput(
                    prev_txid=utxo['txid'],
                    prev_vout=utxo['vout'],
                    script_sig=b"signature_placeholder",
                    sequence=0xffffffff
                ))
            
            # Create transaction outputs
            outputs = []
            
            # Output to recipient
            outputs.append(TransactionOutput(
                value=amount_satoshis,
                script_pubkey=b"recipient_output",
                address=to_address
            ))
            
            # Change output (if needed)
            change_amount = total_input_value - total_needed
            if change_amount > 0:
                outputs.append(TransactionOutput(
                    value=change_amount,
                    script_pubkey=b"change_output",
                    address=from_address
                ))
            
            # Create transaction
            transaction = Transaction(
                version=1,
                inputs=inputs,
                outputs=outputs,
                lock_time=0,
                fee=fee_satoshis
            )
            
            return transaction
            
        except Exception as e:
            print(f"Transaction creation error: {e}")
            return None

    def create_quantum_transaction(self, from_address: str, to_address: str, amount_wepo: float, 
                                 private_key: bytes, public_key: bytes, fee_wepo: float = 0.0001) -> Optional[Transaction]:
        """Create a quantum-signed transaction"""
        try:
            # Validate quantum address format
            if not (from_address.startswith("wepo1") and len(from_address) == 45):
                print(f"Invalid quantum address format: {from_address}")
                return None
            
            amount_satoshis = int(amount_wepo * COIN)
            fee_satoshis = int(fee_wepo * COIN)
            total_needed = amount_satoshis + fee_satoshis
            
            # Get available UTXOs for sender
            available_utxos = self.get_utxos_for_address(from_address)
            
            if not available_utxos:
                print(f"No UTXOs available for quantum address: {from_address}")
                return None
            
            # Select UTXOs
            selected_utxos = []
            total_input_value = 0
            
            for utxo in available_utxos:
                selected_utxos.append(utxo)
                total_input_value += utxo['amount']
                if total_input_value >= total_needed:
                    break
            
            if total_input_value < total_needed:
                print(f"Insufficient funds: need {total_needed}, have {total_input_value}")
                return None
            
            # Create transaction inputs (without signatures first)
            inputs = []
            for utxo in selected_utxos:
                inputs.append(TransactionInput(
                    prev_txid=utxo['txid'],
                    prev_vout=utxo['vout'],
                    script_sig=None,  # No script_sig for quantum transactions
                    sequence=0xffffffff,
                    quantum_signature=None,  # Will be filled after signing
                    quantum_public_key=public_key,
                    signature_type="dilithium"
                ))
            
            # Create transaction outputs
            outputs = []
            
            # Output to recipient
            outputs.append(TransactionOutput(
                value=amount_satoshis,
                script_pubkey=None,  # No script_pubkey for quantum transactions
                address=to_address
            ))
            
            # Change output (if needed)
            change_amount = total_input_value - total_needed
            if change_amount > 0:
                outputs.append(TransactionOutput(
                    value=change_amount,
                    script_pubkey=None,
                    address=from_address
                ))
            
            # Create transaction
            transaction = Transaction(
                version=1,
                inputs=inputs,
                outputs=outputs,
                lock_time=0,
                fee=fee_satoshis
            )
            
            # Sign all inputs with quantum signatures
            for i, inp in enumerate(transaction.inputs):
                signing_message = transaction.get_signing_message_for_input(i)
                
                # Import quantum signing
                from dilithium import sign_message
                
                # Create quantum signature
                quantum_signature = sign_message(signing_message, private_key)
                
                # Update input with signature
                inp.quantum_signature = quantum_signature
            
            print(f"✓ Quantum transaction created with {len(inputs)} inputs")
            return transaction
            
        except Exception as e:
            print(f"Quantum transaction creation error: {e}")
            import traceback
            traceback.print_exc()
            return None
            
            # Create transaction
            transaction = Transaction(
                version=1,
                inputs=inputs,
                outputs=outputs,
                lock_time=0,
                fee=fee_satoshis
            )
            
            return transaction
            
        except Exception as e:
            print(f"Error creating transaction: {e}")
            return None
    
    def get_masternode_collateral_for_height(self, block_height: int) -> int:
        """Get masternode collateral required at specific block height"""
        
        # Find the applicable collateral amount from the schedule
        applicable_collateral = 10000 * COIN  # Default to genesis amount
        
        for milestone_height in sorted(DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE.keys(), reverse=True):
            if block_height >= milestone_height:
                applicable_collateral = DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE[milestone_height]
                break
        
        return applicable_collateral
    
    def get_masternode_collateral_info(self, block_height: int) -> dict:
        """Get comprehensive masternode collateral information"""
        
        current_collateral = self.get_masternode_collateral_for_height(block_height)
        
        # Find next reduction
        next_reduction = None
        for milestone_height, collateral in sorted(DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE.items()):
            if milestone_height > block_height:
                next_reduction = {
                    "block_height": milestone_height,
                    "new_collateral": collateral / COIN,  # Convert to WEPO
                    "blocks_until": milestone_height - block_height,
                    "years_until": (milestone_height - block_height) / 525600  # Assuming 1 minute blocks
                }
                break
        
        return {
            "current_collateral": current_collateral / COIN,  # Convert to WEPO
            "current_height": block_height,
            "next_reduction": next_reduction,
            "schedule": {height: amount / COIN for height, amount in DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE.items()}
        }
    
    def create_stake(self, staker_address: str, amount_wepo: float) -> Optional[str]:
        """Create a new stake"""
        try:
            amount_satoshis = int(amount_wepo * COIN)
            
            # Check minimum stake amount
            if amount_satoshis < MIN_STAKE_AMOUNT:
                print(f"Minimum stake amount is {MIN_STAKE_AMOUNT / COIN} WEPO")
                return None
            
            # Check if PoS is activated
            current_height = self.get_block_height()
            if current_height < POS_ACTIVATION_HEIGHT:
                print(f"PoS not activated yet. Activation at height {POS_ACTIVATION_HEIGHT}")
                return None
            
            # Check staker balance
            balance = self.get_balance(staker_address)
            if balance < amount_satoshis:
                print(f"Insufficient balance for staking")
                return None
            
            # Generate stake ID
            stake_id = hashlib.sha256(f"{staker_address}{amount_satoshis}{time.time()}".encode()).hexdigest()
            
            # Create stake record
            stake_info = StakeInfo(
                stake_id=stake_id,
                staker_address=staker_address,
                amount=amount_satoshis,
                start_height=current_height + 1,
                start_time=int(time.time())
            )
            
            # Save to database
            self.conn.execute('''
                INSERT INTO stakes (stake_id, staker_address, amount, start_height, start_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (stake_id, staker_address, amount_satoshis, current_height + 1, int(time.time())))
            
            self.conn.commit()
            
            print(f"✅ Stake created: {amount_wepo} WEPO from {staker_address}")
            print(f"   Stake ID: {stake_id}")
            
            return stake_id
            
        except Exception as e:
            print(f"Error creating stake: {e}")
            return None
    
    def create_masternode(self, operator_address: str, collateral_txid: str, collateral_vout: int, ip_address: str = None, port: int = 22567) -> Optional[str]:
        """Create a new masternode"""
        try:
            # Check if PoS is activated
            current_height = self.get_block_height()
            if current_height < POS_ACTIVATION_HEIGHT:
                print(f"Masternode activation not available yet. Activation at height {POS_ACTIVATION_HEIGHT}")
                return None
            
            # Verify collateral UTXO exists and has correct amount
            cursor = self.conn.execute('''
                SELECT amount, spent FROM utxos 
                WHERE txid = ? AND vout = ?
            ''', (collateral_txid, collateral_vout))
            
            utxo = cursor.fetchone()
            if not utxo:
                print(f"Collateral UTXO not found: {collateral_txid}:{collateral_vout}")
                return None
            
            if utxo[1]:  # spent flag
                print(f"Collateral UTXO already spent")
                return None
            
            # Get dynamic collateral requirement for current height
            required_collateral = self.get_masternode_collateral_for_height(current_height)
            
            if utxo[0] < required_collateral:
                print(f"Insufficient collateral. Required: {required_collateral / COIN} WEPO")
                return None
            
            # Generate masternode ID
            masternode_id = hashlib.sha256(f"{operator_address}{collateral_txid}{time.time()}".encode()).hexdigest()
            
            # Create masternode record
            masternode_info = MasternodeInfo(
                masternode_id=masternode_id,
                operator_address=operator_address,
                collateral_txid=collateral_txid,
                collateral_vout=collateral_vout,
                ip_address=ip_address,
                port=port,
                start_height=current_height + 1,
                start_time=int(time.time()),
                last_ping=int(time.time())
            )
            
            # Save to database
            self.conn.execute('''
                INSERT INTO masternodes (masternode_id, operator_address, collateral_txid, collateral_vout, 
                                       ip_address, port, start_height, start_time, last_ping)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (masternode_id, operator_address, collateral_txid, collateral_vout, 
                  ip_address, port, current_height + 1, int(time.time()), int(time.time())))
            
            self.conn.commit()
            
            print(f"✅ Masternode created: {operator_address}")
            print(f"   Masternode ID: {masternode_id}")
            print(f"   Collateral: {collateral_txid}:{collateral_vout}")
            
            return masternode_id
            
        except Exception as e:
            print(f"Error creating masternode: {e}")
            return None
    
    def get_active_stakes(self) -> List[StakeInfo]:
        """Get all active stakes"""
        cursor = self.conn.execute('''
            SELECT stake_id, staker_address, amount, start_height, start_time, 
                   last_reward_height, total_rewards, status, unlock_height
            FROM stakes WHERE status = 'active'
        ''')
        
        stakes = []
        for row in cursor.fetchall():
            stakes.append(StakeInfo(
                stake_id=row[0],
                staker_address=row[1],
                amount=row[2],
                start_height=row[3],
                start_time=row[4],
                last_reward_height=row[5],
                total_rewards=row[6],
                status=row[7],
                unlock_height=row[8]
            ))
        
        return stakes
    
    def get_active_masternodes(self) -> List[MasternodeInfo]:
        """Get all active masternodes"""
        cursor = self.conn.execute('''
            SELECT masternode_id, operator_address, collateral_txid, collateral_vout,
                   ip_address, port, start_height, start_time, last_ping, status, total_rewards
            FROM masternodes WHERE status = 'active'
        ''')
        
        masternodes = []
        for row in cursor.fetchall():
            masternodes.append(MasternodeInfo(
                masternode_id=row[0],
                operator_address=row[1],
                collateral_txid=row[2],
                collateral_vout=row[3],
                ip_address=row[4],
                port=row[5],
                start_height=row[6],
                start_time=row[7],
                last_ping=row[8],
                status=row[9],
                total_rewards=row[10]
            ))
        
        return masternodes
    
    def calculate_staking_rewards(self, block_height: int) -> Dict[str, int]:
        """Calculate staking rewards for a block"""
        rewards = {}
        
        # Only distribute PoS rewards after activation
        if block_height < POS_ACTIVATION_HEIGHT:
            return rewards
        
        # Get active stakes and masternodes
        active_stakes = self.get_active_stakes()
        active_masternodes = self.get_active_masternodes()
        
        if not active_stakes and not active_masternodes:
            return rewards
        
        # Calculate total block reward for PoS (50% of total after year 1)
        total_pos_reward = self.calculate_pos_reward(block_height)
        
        if total_pos_reward <= 0:
            return rewards
        
        # 60% to stakers, 40% to masternodes
        staking_reward_pool = int(total_pos_reward * 0.6)
        masternode_reward_pool = int(total_pos_reward * 0.4)
        
        # Distribute staking rewards proportionally
        if active_stakes and staking_reward_pool > 0:
            total_stake_amount = sum(stake.amount for stake in active_stakes)
            
            for stake in active_stakes:
                proportion = stake.amount / total_stake_amount
                reward = int(staking_reward_pool * proportion)
                if reward > 0:
                    rewards[stake.staker_address] = rewards.get(stake.staker_address, 0) + reward
        
        # Distribute masternode rewards equally
        if active_masternodes and masternode_reward_pool > 0:
            reward_per_masternode = masternode_reward_pool // len(active_masternodes)
            
            for masternode in active_masternodes:
                if reward_per_masternode > 0:
                    rewards[masternode.operator_address] = rewards.get(masternode.operator_address, 0) + reward_per_masternode
        
        return rewards
    
    def calculate_pos_reward(self, block_height: int) -> int:
        """Calculate PoS reward amount for a block"""
        if block_height < POS_ACTIVATION_HEIGHT:
            return 0
        
        # After year 1, PoS gets 50% of block rewards
        if block_height >= POW_BLOCKS_YEAR1:
            base_reward = REWARD_YEAR2_BASE
            
            # Apply halvings every 4 years
            halvings = (block_height - POW_BLOCKS_YEAR1) // HALVING_INTERVAL
            for _ in range(halvings):
                base_reward //= 2
            
            return int(base_reward * 0.5)  # 50% to PoS
        
        return 0
    
    def distribute_staking_rewards(self, block_height: int, block_hash: str):
        """Distribute staking rewards for a block"""
        try:
            rewards = self.calculate_staking_rewards(block_height)
            
            for address, reward_amount in rewards.items():
                # Create reward UTXO
                reward_txid = f"pos_reward_{block_height}_{address}_{int(time.time())}"
                
                self.conn.execute('''
                    INSERT INTO utxos (txid, vout, address, amount, script_pubkey, spent)
                    VALUES (?, ?, ?, ?, ?, FALSE)
                ''', (reward_txid, 0, address, reward_amount, b"pos_reward"))
                
                # Record reward in history
                reward_id = hashlib.sha256(f"{reward_txid}{address}{block_height}".encode()).hexdigest()
                
                self.conn.execute('''
                    INSERT INTO staking_rewards (reward_id, recipient_address, recipient_type, 
                                               amount, block_height, block_hash, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (reward_id, address, 'staker', reward_amount, block_height, block_hash, int(time.time())))
                
                print(f"💰 PoS reward: {reward_amount / COIN} WEPO to {address}")
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Error distributing staking rewards: {e}")
    
    def get_staking_info(self) -> dict:
        """Get comprehensive staking system information"""
        try:
            current_height = self.get_block_height()
            total_staked = self.get_total_staked()
            active_stakes = self.get_active_stakes()
            
            # Calculate time until PoS activation (for mainnet)
            activation_info = self.get_pos_activation_info()
            
            return {
                "staking_enabled": current_height >= POS_ACTIVATION_HEIGHT,
                "pos_activation_height": POS_ACTIVATION_HEIGHT,
                "current_height": current_height,
                "blocks_until_activation": max(0, POS_ACTIVATION_HEIGHT - current_height),
                "production_mode": PRODUCTION_MODE,
                "christmas_launch": datetime.fromtimestamp(CHRISTMAS_GENESIS_TIMESTAMP).isoformat(),
                "staking_activation_date": activation_info["activation_date"],
                "days_until_staking": activation_info["days_until_activation"],
                "min_stake_amount": MIN_STAKE_AMOUNT / COIN,
                "min_masternode_collateral": self.get_masternode_collateral_for_height(current_height) / COIN,
                "total_staked": total_staked / COIN,
                "active_stakes_count": len(active_stakes),
                "total_stakers": len(set(stake.staker_address for stake in active_stakes)),
                "staking_apy": self.calculate_staking_apy(),
                "fee_distribution": {
                    "masternodes": "60%",
                    "miners": "25%", 
                    "stakers": "15%"
                }
            }
            
        except Exception as e:
            print(f"Error getting staking info: {e}")
            return {"error": str(e)}
    
    def get_pos_activation_info(self) -> dict:
        """Get PoS activation timing information"""
        try:
            if PRODUCTION_MODE:
                return {
                    "activation_date": "Immediately (Production Mode)",
                    "days_until_activation": 0,
                    "activation_timestamp": int(time.time())
                }
            else:
                # Calculate activation date from Christmas launch
                activation_timestamp = CHRISTMAS_GENESIS_TIMESTAMP + STAKING_ACTIVATION_DELAY
                activation_date = datetime.fromtimestamp(activation_timestamp)
                days_until = max(0, (activation_timestamp - time.time()) / (24 * 60 * 60))
                
                return {
                    "activation_date": activation_date.strftime("%B %d, %Y at %I:%M %p EST"),
                    "days_until_activation": int(days_until),
                    "activation_timestamp": activation_timestamp
                }
                
        except Exception as e:
            return {
                "activation_date": "Error calculating date",
                "days_until_activation": -1,
                "activation_timestamp": 0
            }
    
    def calculate_staking_apy(self) -> float:
        """Calculate estimated annual percentage yield for staking"""
        try:
            # Simplified APY calculation based on 15% of all fees
            # This would be more sophisticated in production with historical data
            total_staked = self.get_total_staked()
            if total_staked == 0:
                return 0.0
            
            # Estimate based on network activity and fee generation
            # Assumption: Network generates fees worth 1% of total supply annually
            estimated_annual_fees = 21000000 * 0.01 * COIN  # 1% of 21M WEPO
            staker_share = estimated_annual_fees * 0.15  # 15% goes to stakers
            
            if total_staked > 0:
                apy = (staker_share / total_staked) * 100
                return min(apy, 25.0)  # Cap at 25% APY for display
            
            return 0.0
            
        except Exception as e:
            print(f"Error calculating staking APY: {e}")
            return 0.0
    
    def activate_production_staking(self) -> dict:
        """Activate staking for production testing"""
        try:
            global PRODUCTION_MODE, POS_ACTIVATION_HEIGHT
            
            if not PRODUCTION_MODE:
                PRODUCTION_MODE = True
                POS_ACTIVATION_HEIGHT = max(1, self.get_block_height())
                
                return {
                    "success": True,
                    "message": "Production staking activated immediately",
                    "pos_activation_height": POS_ACTIVATION_HEIGHT,
                    "staking_enabled": True,
                    "min_stake_amount": MIN_STAKE_AMOUNT / COIN,
                    "fee_distribution_active": True
                }
            else:
                return {
                    "success": True,
                    "message": "Production staking already active",
                    "pos_activation_height": POS_ACTIVATION_HEIGHT,
                    "staking_enabled": True
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_total_staked(self) -> int:
        """Get total amount staked across all stakers"""
        try:
            cursor = self.conn.execute('SELECT SUM(amount) FROM stakes WHERE status = "active"')
            result = cursor.fetchone()
            return result[0] if result and result[0] else 0
        except Exception as e:
            print(f"Error getting total staked: {e}")
            return 0

    def get_blockchain_info(self) -> dict:
        """Get blockchain information"""
        return {
            'height': self.get_block_height(),
            'best_block_hash': self.get_latest_block().get_block_hash() if self.chain else None,
            'difficulty': self.current_difficulty,
            'mempool_size': len(self.mempool),
            'total_supply': sum(self.calculate_block_reward(i) for i in range(len(self.chain))),
            'network': 'mainnet',
            'version': WEPO_VERSION
        }

def main():
    """Main function for testing the blockchain"""
    print("=== WEPO Blockchain Core ===")
    print("Revolutionary Cryptocurrency - We The People")
    print()
    
    # Initialize blockchain
    blockchain = WepoBlockchain()
    
    # Print initial state
    info = blockchain.get_blockchain_info()
    print("Initial blockchain state:")
    for key, value in info.items():
        print(f"  {key}: {value}")
    print()
    
    # Mine some blocks
    miner_address = "wepo1miner0000000000000000000000000"
    
    for i in range(3):
        print(f"\n--- Mining Block {i + 1} ---")
        mined_block = blockchain.mine_next_block(miner_address)
        
        if mined_block:
            print(f"Successfully mined block {mined_block.height}")
            print(f"Block hash: {mined_block.get_block_hash()}")
            print(f"Transactions: {len(mined_block.transactions)}")
            print(f"Block reward: {blockchain.calculate_block_reward(mined_block.height) / COIN} WEPO")
        else:
            print("Failed to mine block")
            break
    
    # Print final state
    print("\n--- Final Blockchain State ---")
    final_info = blockchain.get_blockchain_info()
    for key, value in final_info.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()