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

# WEPO 20-YEAR MINING SCHEDULE - SUSTAINABLE LONG-TERM POW
# Genesis: December 25, 2025, 3:00 PM EST
GENESIS_TIME = 1735138800  # Christmas Day 2025

# Total Supply - DEFINITIVE VALUE
TOTAL_SUPPLY = 69000003  # 69,000,003 WEPO total supply

# Block Time Configuration
BLOCK_TIME_TARGET = BLOCK_TIME_INITIAL_18_MONTHS = 360  # 6 minutes per block (first 18 months)
BLOCK_TIME_YEAR1 = BLOCK_TIME_INITIAL_18_MONTHS  # For backward compatibility
BLOCK_TIME_LONGTERM = 540           # 9 minutes per block (post-18 months)

# PHASE 1: Pre-PoS Mining (Months 1-18) - 10% of total supply
PRE_POS_DURATION_BLOCKS = 131400    # 18 months in 6-minute blocks
PRE_POS_REWARD = int(6900000 * COIN / PRE_POS_DURATION_BLOCKS)  # 52.51 WEPO per block
PRE_POS_TOTAL_SUPPLY = 6900000 * COIN  # 6.9M WEPO (10% of total)

# Long-term PoW phases (alongside PoS/Masternodes) - 20% of total supply
BLOCKS_PER_YEAR_LONGTERM = int(365.25 * 24 * 60 / 9)  # 58,400 blocks per year (9-min blocks)

# PHASE 2A: Post-PoS Years 1-3 (Months 19-54)
PHASE_2A_BLOCKS = 3 * BLOCKS_PER_YEAR_LONGTERM  # 175,200 blocks
PHASE_2A_REWARD = int(33.17 * COIN)  # 33.17 WEPO per block
PHASE_2A_END_HEIGHT = PRE_POS_DURATION_BLOCKS + PHASE_2A_BLOCKS

# PHASE 2B: Post-PoS Years 4-9 (Months 55-126) - First Halving
PHASE_2B_BLOCKS = 6 * BLOCKS_PER_YEAR_LONGTERM  # 350,400 blocks
PHASE_2B_REWARD = int(16.58 * COIN)  # 16.58 WEPO per block (halved)
PHASE_2B_END_HEIGHT = PHASE_2A_END_HEIGHT + PHASE_2B_BLOCKS

# PHASE 2C: Post-PoS Years 10-12 (Months 127-162) - Second Halving
PHASE_2C_BLOCKS = 3 * BLOCKS_PER_YEAR_LONGTERM  # 175,200 blocks
PHASE_2C_REWARD = int(8.29 * COIN)  # 8.29 WEPO per block (halved)
PHASE_2C_END_HEIGHT = PHASE_2B_END_HEIGHT + PHASE_2C_BLOCKS

# PHASE 2D: Post-PoS Years 13-15 (Months 163-198) - Final Halving
PHASE_2D_BLOCKS = 3 * BLOCKS_PER_YEAR_LONGTERM  # 175,200 blocks
PHASE_2D_REWARD = int(4.15 * COIN)  # 4.15 WEPO per block (final halving)
PHASE_2D_END_HEIGHT = PHASE_2C_END_HEIGHT + PHASE_2D_BLOCKS

# Total PoW ends at block 1,007,400 (16.5 years after PoS activation)
POW_END_HEIGHT = PHASE_2D_END_HEIGHT

# Total mining allocation: 20,702,037 WEPO over 198 months (30% of total supply)
TOTAL_POW_SUPPLY = 20702037 * COIN

# Legacy constants - kept for backward compatibility
TOTAL_INITIAL_BLOCKS = PRE_POS_DURATION_BLOCKS  # For PoS activation timing
POW_BLOCKS_YEAR1 = 52560      # OLD: 10-min blocks for 1 year (not used in new schedule)
REWARD_Q1 = 400 * COIN        # OLD: 400 WEPO per block Q1 (not used in new schedule)
REWARD_Q2 = 200 * COIN        # OLD: 200 WEPO per block Q2 (not used in new schedule)
REWARD_Q3 = 100 * COIN        # OLD: 100 WEPO per block Q3 (not used in new schedule)
REWARD_Q4 = 50 * COIN         # OLD: 50 WEPO per block Q4 (not used in new schedule)
REWARD_YEAR2_BASE = 12.4 * COIN # OLD: 12.4 WEPO per block year 2+ (not used in new schedule)
HALVING_INTERVAL = 1051200    # OLD: Blocks between halvings (not used in new schedule)

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
    POS_ACTIVATION_HEIGHT = TOTAL_INITIAL_BLOCKS  # 131,400 blocks (18 months)
    print(f"🎄 MAINNET READY: Staking activates at block {POS_ACTIVATION_HEIGHT} (18 months post-genesis)")
    print(f"🔄 PoW CONTINUES: Mining continues for 198 months total alongside PoS/Masternodes")

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
    """WEPO Block Header with Hybrid PoW/PoS Support"""
    version: int
    prev_hash: str
    merkle_root: str
    timestamp: int
    bits: int
    nonce: int
    consensus_type: str  # 'pow', 'pos', or 'hybrid'
    validator_address: Optional[str] = None  # For PoS blocks
    validator_signature: Optional[bytes] = None  # For PoS blocks
    
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
    
    def is_pos_block(self) -> bool:
        """Check if this is a PoS block"""
        return self.consensus_type == 'pos'
    
    def is_pow_block(self) -> bool:
        """Check if this is a PoW block"""
        return self.consensus_type == 'pow'

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
        """Calculate block reward based on new 20-year sustainable mining schedule"""
        
        # PHASE 1: Pre-PoS Mining (Months 1-18) - 10% of supply
        if height <= PRE_POS_DURATION_BLOCKS:
            # Months 1-18: 52.51 WEPO per block (6-minute blocks)
            return PRE_POS_REWARD
        
        # PHASE 2A: Post-PoS Years 1-3 (Months 19-54)
        elif height <= PHASE_2A_END_HEIGHT:
            # Years 1-3: 33.17 WEPO per block (9-minute blocks)
            return PHASE_2A_REWARD
        
        # PHASE 2B: Post-PoS Years 4-9 (Months 55-126) - First Halving
        elif height <= PHASE_2B_END_HEIGHT:
            # Years 4-9: 16.58 WEPO per block (9-minute blocks)
            return PHASE_2B_REWARD
        
        # PHASE 2C: Post-PoS Years 10-12 (Months 127-162) - Second Halving  
        elif height <= PHASE_2C_END_HEIGHT:
            # Years 10-12: 8.29 WEPO per block (9-minute blocks)
            return PHASE_2C_REWARD
        
        # PHASE 2D: Post-PoS Years 13-15 (Months 163-198) - Final Halving
        elif height <= PHASE_2D_END_HEIGHT:
            # Years 13-15: 4.15 WEPO per block (9-minute blocks)
            return PHASE_2D_REWARD
        
        else:
            # PoW ENDS at block 1,007,400 (Month 198)
            # Miners continue earning through 25% fee redistribution
            return 0
        
        # TOTAL MINING TIMELINE:
        # - Phase 1 (18 months): 6.9M WEPO (10% of supply)
        # - Phase 2A-2D (16.5 years): 13.8M WEPO (20% of supply)
        # - Total PoW: 20.7M WEPO over 198 months (30% of supply)
        # - PoS/Masternodes: 48.3M WEPO (70% of supply)
        # - Post-PoW: Miners earn via 25% transaction fee redistribution
    
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
        block = Block(
            header=header,
            transactions=transactions,
            height=height
        )
        
        # Calculate merkle root
        block.header.merkle_root = block.calculate_merkle_root()
        
        return block
    
    def mine_block(self, miner_address: str) -> Optional[Block]:
        """Mine a new block"""
        block = self.create_new_block(miner_address)
        
        # Adjust difficulty if needed
        self.adjust_difficulty()
        
        # Mine the block
        mined_block = self.miner.mine_block(block, self.current_difficulty)
        
        if mined_block:
            # Add block to chain
            if self.add_block(mined_block):
                return mined_block
        
        return None
    
    def add_block(self, block: Block, validate: bool = True) -> bool:
        """Add a block to the blockchain"""
        if validate and not self.validate_block(block):
            return False
        
        # Add to chain
        self.chain.append(block)
        
        # Process transactions and update UTXOs
        self.process_block_transactions(block)
        
        # Save to database
        self.save_block(block)
        
        # Distribute staking rewards if PoS is active
        if block.height >= POS_ACTIVATION_HEIGHT:
            self.distribute_staking_rewards(block.height, block.get_block_hash())
        
        print(f"Block {block.height} added to chain: {block.get_block_hash()}")
        return True
    
    def validate_block(self, block: Block) -> bool:
        """Validate a block"""
        # Basic validation
        if not block.transactions:
            return False
        
        # Check coinbase transaction
        if not block.transactions[0].is_coinbase():
            return False
        
        # Validate all transactions
        for tx in block.transactions:
            if not self.validate_transaction(tx):
                return False
        
        return True
    
    def process_block_transactions(self, block: Block):
        """Process all transactions in a block and update UTXOs"""
        for tx in block.transactions:
            # Process transaction inputs (spend UTXOs)
            if not tx.is_coinbase():
                for inp in tx.inputs:
                    # Mark UTXO as spent
                    self.conn.execute('''
                        UPDATE utxos SET spent = TRUE, spent_txid = ?, spent_height = ?
                        WHERE txid = ? AND vout = ?
                    ''', (tx.calculate_txid(), block.height, inp.prev_txid, inp.prev_vout))
            
            # Process transaction outputs (create new UTXOs)
            for i, out in enumerate(tx.outputs):
                self.conn.execute('''
                    INSERT INTO utxos (txid, vout, address, amount, script_pubkey, spent)
                    VALUES (?, ?, ?, ?, ?, FALSE)
                ''', (tx.calculate_txid(), i, out.address, out.value, out.script_pubkey))
        
        self.conn.commit()
    
    def save_block(self, block: Block):
        """Save block to database"""
        # Save block
        self.conn.execute('''
            INSERT INTO blocks (height, hash, prev_hash, merkle_root, timestamp, bits, nonce, version, size, tx_count, consensus_type, block_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            self.conn.execute('''
                INSERT INTO transactions (txid, block_height, block_hash, version, lock_time, fee, privacy_proof, ring_signature, tx_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tx.calculate_txid(),
                block.height,
                block.get_block_hash(),
                tx.version,
                tx.lock_time,
                tx.fee,
                tx.privacy_proof,
                tx.ring_signature,
                json.dumps(asdict(tx), default=str)
            ))
        
        self.conn.commit()
    
    def adjust_difficulty(self):
        """Adjust mining difficulty based on block time"""
        if len(self.chain) < 10:
            return
        
        # Calculate average block time over last 10 blocks
        recent_blocks = self.chain[-10:]
        time_diffs = []
        for i in range(1, len(recent_blocks)):
            diff = recent_blocks[i].header.timestamp - recent_blocks[i-1].header.timestamp
            time_diffs.append(diff)
        
        avg_time = sum(time_diffs) / len(time_diffs)
        
        # Determine target time based on current height
        current_height = self.get_block_height()
        if current_height <= TOTAL_INITIAL_BLOCKS:
            target_time = BLOCK_TIME_INITIAL_18_MONTHS
        else:
            target_time = BLOCK_TIME_LONGTERM
        
        # Adjust difficulty
        if avg_time < target_time * 0.75:
            # Blocks too fast, increase difficulty
            self.current_difficulty += 1
            print(f"Difficulty increased to {self.current_difficulty}")
        elif avg_time > target_time * 1.25:
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
            for inp in transaction.inputs:
                # Check if UTXO exists and is unspent
                cursor = self.conn.execute('''
                    SELECT amount, spent FROM utxos WHERE txid = ? AND vout = ?
                ''', (inp.prev_txid, inp.prev_vout))
                
                utxo = cursor.fetchone()
                if not utxo:
                    print(f"UTXO not found: {inp.prev_txid}:{inp.prev_vout}")
                    return False
                
                if utxo[1]:  # spent flag
                    print(f"UTXO already spent: {inp.prev_txid}:{inp.prev_vout}")
                    return False
                
                total_input_value += utxo[0]
            
            # Check outputs
            total_output_value = sum(out.value for out in transaction.outputs)
            
            # Calculate fee
            fee = total_input_value - total_output_value
            if fee < 0:
                print(f"Transaction outputs exceed inputs: {total_output_value} > {total_input_value}")
                return False
            
            # Set fee on transaction
            transaction.fee = fee
            
            # Validate quantum signatures if present
            for i, inp in enumerate(transaction.inputs):
                if inp.signature_type == "dilithium":
                    if not transaction.verify_quantum_signature(i):
                        print(f"Invalid quantum signature for input {i}")
                        return False
            
            return True
            
        except Exception as e:
            print(f"Transaction validation error: {e}")
            return False
    
    def get_balance(self, address: str) -> int:
        """Get balance for an address"""
        cursor = self.conn.execute('''
            SELECT SUM(amount) FROM utxos WHERE address = ? AND spent = FALSE
        ''')
        result = cursor.fetchone()
        return result[0] if result[0] else 0
    
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
                'script_pubkey': row[3]
            })
        
        return utxos
    
    def create_transaction(self, from_address: str, to_address: str, amount: int, fee: int = 10000) -> Optional[Transaction]:
        """Create a transaction"""
        # Get UTXOs for sender
        utxos = self.get_utxos_for_address(from_address)
        
        if not utxos:
            print(f"No UTXOs found for address {from_address}")
            return None
        
        # Calculate total available
        total_available = sum(utxo['amount'] for utxo in utxos)
        
        if total_available < amount + fee:
            print(f"Insufficient balance: {total_available} < {amount + fee}")
            return None
        
        # Create inputs
        inputs = []
        input_total = 0
        
        for utxo in utxos:
            inputs.append(TransactionInput(
                prev_txid=utxo['txid'],
                prev_vout=utxo['vout'],
                script_sig=b"signature_placeholder",
                sequence=0xffffffff
            ))
            input_total += utxo['amount']
            
            if input_total >= amount + fee:
                break
        
        # Create outputs
        outputs = [TransactionOutput(
            value=amount,
            script_pubkey=b"output_script",
            address=to_address
        )]
        
        # Add change output if needed
        change = input_total - amount - fee
        if change > 0:
            outputs.append(TransactionOutput(
                value=change,
                script_pubkey=b"change_script", 
                address=from_address
            ))
        
        # Create transaction
        transaction = Transaction(
            version=1,
            inputs=inputs,
            outputs=outputs,
            lock_time=0,
            fee=fee
        )
        
        return transaction
    
    # ===== STAKING SYSTEM =====
    
    def create_stake(self, staker_address: str, amount: int) -> str:
        """Create a new stake"""
        if amount < MIN_STAKE_AMOUNT:
            raise ValueError(f"Minimum stake amount is {MIN_STAKE_AMOUNT / COIN} WEPO")
        
        # Check if user has sufficient balance
        balance = self.get_balance(staker_address)
        if balance < amount:
            raise ValueError(f"Insufficient balance: {balance / COIN} WEPO")
        
        # Create stake
        stake_id = f"stake_{staker_address}_{int(time.time())}"
        current_height = self.get_block_height()
        
        stake = StakeInfo(
            stake_id=stake_id,
            staker_address=staker_address,
            amount=amount,
            start_height=current_height,
            start_time=int(time.time())
        )
        
        # Save to database
        self.conn.execute('''
            INSERT INTO stakes (stake_id, staker_address, amount, start_height, start_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (stake_id, staker_address, amount, current_height, int(time.time())))
        
        self.conn.commit()
        
        # Store in memory
        self.stakes[stake_id] = asdict(stake)
        
        print(f"Created stake: {stake_id} for {amount / COIN} WEPO")
        return stake_id
    
    def create_masternode(self, operator_address: str, collateral_txid: str, collateral_vout: int, ip_address: str = None) -> str:
        """Create a new masternode"""
        current_height = self.get_block_height()
        required_collateral = self.get_masternode_collateral_for_height(current_height)
        
        # Verify collateral UTXO exists and has correct amount
        cursor = self.conn.execute('''
            SELECT amount, spent FROM utxos WHERE txid = ? AND vout = ?
        ''', (collateral_txid, collateral_vout))
        
        utxo = cursor.fetchone()
        if not utxo or utxo[1] or utxo[0] < required_collateral:
            raise ValueError(f"Invalid collateral UTXO or insufficient amount")
        
        # Create masternode
        masternode_id = f"mn_{operator_address}_{int(time.time())}"
        
        masternode = MasternodeInfo(
            masternode_id=masternode_id,
            operator_address=operator_address,
            collateral_txid=collateral_txid,
            collateral_vout=collateral_vout,
            ip_address=ip_address,
            start_height=current_height,
            start_time=int(time.time())
        )
        
        # Save to database
        self.conn.execute('''
            INSERT INTO masternodes (masternode_id, operator_address, collateral_txid, collateral_vout, ip_address, start_height, start_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (masternode_id, operator_address, collateral_txid, collateral_vout, ip_address, current_height, int(time.time())))
        
        self.conn.commit()
        
        # Store in memory
        self.masternodes[masternode_id] = asdict(masternode)
        
        print(f"Created masternode: {masternode_id}")
        return masternode_id
    
    def get_masternode_collateral_for_height(self, height: int) -> int:
        """Get required masternode collateral for a specific height"""
        for trigger_height in sorted(DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE.keys(), reverse=True):
            if height >= trigger_height:
                return DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE[trigger_height]
        return DYNAMIC_MASTERNODE_COLLATERAL_SCHEDULE[0]
    
    def get_active_stakes(self) -> List[StakeInfo]:
        """Get all active stakes"""
        cursor = self.conn.execute('''
            SELECT stake_id, staker_address, amount, start_height, start_time, last_reward_height, total_rewards, status, unlock_height
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
            SELECT masternode_id, operator_address, collateral_txid, collateral_vout, ip_address, port, start_height, start_time, last_ping, status, total_rewards
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
                rewards[masternode.operator_address] = rewards.get(masternode.operator_address, 0) + reward_per_masternode
        
        return rewards
    
    def calculate_pos_reward(self, block_height: int) -> int:
        """Calculate PoS reward for a block height"""
        if block_height < POS_ACTIVATION_HEIGHT:
            return 0
        
        # After PoS activation, use a decreasing reward schedule
        # This is separate from PoW rewards and represents newly minted coins for PoS
        years_since_pos = (block_height - POS_ACTIVATION_HEIGHT) // (365 * 24 * 60 // 9)  # 9-min blocks
        
        if years_since_pos < 2:
            base_reward = 25 * COIN  # 25 WEPO per block for first 2 years
        elif years_since_pos < 5:
            base_reward = 12.5 * COIN  # 12.5 WEPO per block for years 2-5
        elif years_since_pos < 10:
            base_reward = 6.25 * COIN  # 6.25 WEPO per block for years 5-10
        else:
            # Continue halving every 5 years
            halvings = (years_since_pos - 10) // 5
            base_reward = 6.25 * COIN
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
                self.conn.execute('''
                    INSERT INTO staking_rewards (reward_id, recipient_address, recipient_type, amount, block_height, block_hash, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (f"reward_{block_height}_{address}", address, "staker", reward_amount, block_height, block_hash, int(time.time())))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"Error distributing staking rewards: {e}")
    
    def get_staking_info(self) -> dict:
        """Get staking system information"""
        try:
            current_height = self.get_block_height()
            active_stakes = self.get_active_stakes()
            total_staked = sum(stake.amount for stake in active_stakes)
            
            # Calculate activation info
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
                    "activation_timestamp": 0
                }
            else:
                # Calculate 18 months from Christmas launch
                activation_timestamp = CHRISTMAS_GENESIS_TIMESTAMP + STAKING_ACTIVATION_DELAY
                activation_date = datetime.fromtimestamp(activation_timestamp).isoformat()
                
                # Calculate days until activation
                current_time = int(time.time())
                days_until = max(0, (activation_timestamp - current_time) // (24 * 60 * 60))
                
                return {
                    "activation_date": activation_date,
                    "days_until_activation": days_until,
                    "activation_timestamp": activation_timestamp
                }
        except Exception as e:
            return {
                "activation_date": "Error calculating",
                "days_until_activation": 0,
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
            estimated_annual_fees = TOTAL_SUPPLY * 0.01  # 1% of total supply
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
        """Get total amount staked in the network"""
        cursor = self.conn.execute('''
            SELECT SUM(amount) FROM stakes WHERE status = 'active'
        ''')
        result = cursor.fetchone()
        return result[0] if result[0] else 0
    
    def get_network_info(self) -> dict:
        """Get network information"""
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
    """Main function for testing"""
    blockchain = WepoBlockchain()
    
    # Test mining a few blocks
    test_address = "wepo1test00000000000000000000000000000"
    
    for i in range(5):
        print(f"\n--- Mining block {i+1} ---")
        block = blockchain.mine_block(test_address)
        if block:
            print(f"Block {block.height} mined successfully!")
            print(f"Reward: {blockchain.calculate_block_reward(block.height) / COIN} WEPO")
        else:
            print("Mining failed")
            break
    
    # Display network info
    print("\n--- Network Info ---")
    info = blockchain.get_network_info()
    for key, value in info.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()