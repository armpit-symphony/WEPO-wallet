#!/usr/bin/env python3
"""
WEPO Core Blockchain Implementation
Revolutionary cryptocurrency with hybrid PoW/PoS consensus and privacy features
"""

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

# WEPO Network Constants
WEPO_VERSION = 70001
NETWORK_MAGIC = b'WEPO'
DEFAULT_PORT = 22567
GENESIS_TIME = 1704067200  # Jan 1, 2024
BLOCK_TIME_TARGET = 120    # 2 minutes (after year 1)
BLOCK_TIME_YEAR1 = 600     # 10 minutes (year 1)
MAX_BLOCK_SIZE = 2 * 1024 * 1024  # 2MB
COIN = 100000000  # 1 WEPO = 100,000,000 satoshis

# Consensus Parameters
POW_BLOCKS_YEAR1 = 52560      # 10-min blocks for 1 year
REWARD_Q1 = 1000 * COIN       # 1000 WEPO per block Q1 (MEGA REWARDS!)
REWARD_Q2 = 500 * COIN        # 500 WEPO per block Q2
REWARD_Q3 = 250 * COIN        # 250 WEPO per block Q3  
REWARD_Q4 = 125 * COIN        # 125 WEPO per block Q4
REWARD_YEAR2_BASE = 12.4 * COIN # 12.4 WEPO per block year 2+
HALVING_INTERVAL = 1051200    # Blocks between halvings (4 years)
POS_ACTIVATION_HEIGHT = int(POW_BLOCKS_YEAR1 * 1.5)  # 18 months
MIN_STAKE_AMOUNT = 1000 * COIN
MASTERNODE_COLLATERAL = 10000 * COIN

@dataclass
class TransactionInput:
    """Transaction input (UTXO reference)"""
    prev_txid: str
    prev_vout: int
    script_sig: bytes
    sequence: int = 0xffffffff
    
@dataclass 
class TransactionOutput:
    """Transaction output"""
    value: int
    script_pubkey: bytes
    address: str = ""

@dataclass
class Transaction:
    """WEPO Transaction with privacy features"""
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
                value=REWARD_YEAR1,
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
            print(f"Genesis block created: {mined_genesis.get_block_hash()}")
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
                inputs.append(TransactionInput(
                    prev_txid=inp_data['prev_txid'],
                    prev_vout=inp_data['prev_vout'],
                    script_sig=script_sig,
                    sequence=inp_data.get('sequence', 0xffffffff)
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
        """Calculate block reward based on height with aggressive Year 1 schedule"""
        # Year 1: Quarterly halvings starting at 1000 WEPO
        if height <= POW_BLOCKS_YEAR1:
            # Calculate quarter within year 1 (10-minute blocks)
            blocks_per_quarter = POW_BLOCKS_YEAR1 // 4  # 13,140 blocks per quarter
            quarter = height // blocks_per_quarter
            
            if quarter == 0:      # Q1: Months 1-3
                return 1000 * COIN
            elif quarter == 1:    # Q2: Months 4-6  
                return 500 * COIN
            elif quarter == 2:    # Q3: Months 7-9
                return 250 * COIN
            else:                 # Q4: Months 10-12
                return 125 * COIN
        
        # After year 1: Standard schedule with 4-year halvings
        years_since_year2 = (height - POW_BLOCKS_YEAR1) // HALVING_INTERVAL
        reward = REWARD_YEAR2_BASE
        
        # Apply halvings every 4 years
        for _ in range(years_since_year2):
            reward //= 2
        
        return reward
    
    def create_coinbase_transaction(self, height: int, miner_address: str) -> Transaction:
        """Create coinbase transaction for new block"""
        reward = self.calculate_block_reward(height)
        
        return Transaction(
            version=1,
            inputs=[TransactionInput(
                prev_txid="0" * 64,
                prev_vout=0xffffffff,
                script_sig=f"Block {height}".encode(),
                sequence=0xffffffff
            )],
            outputs=[TransactionOutput(
                value=reward,
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
        
        # Create coinbase transaction
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
        block_time = BLOCK_TIME_YEAR1 if height <= POW_BLOCKS_YEAR1 else BLOCK_TIME_TARGET
        
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
        """Add a block to the blockchain"""
        if validate and not self.validate_block(block):
            return False
        
        try:
            # Add to chain
            self.chain.append(block)
            
            # Save to database
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
            
            self.conn.commit()
            
            # Adjust difficulty every 1440 blocks (2 days)
            if block.height % 1440 == 0:
                self.adjust_difficulty()
            
            print(f"Block {block.height} added to blockchain: {block.get_block_hash()}")
            return True
            
        except Exception as e:
            print(f"Error adding block: {e}")
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
            print(f"Transaction added to mempool: {txid}")
            return True
        else:
            print(f"Invalid transaction rejected: {txid}")
            return False
    
    def validate_transaction(self, transaction: Transaction) -> bool:
        """Validate a transaction"""
        try:
            # Skip validation for coinbase transactions
            if transaction.is_coinbase():
                return True
            
            # Check inputs exist and are unspent
            total_input_value = 0
            for inp in transaction.inputs:
                # TODO: Implement UTXO lookup
                # For now, assume valid
                total_input_value += 100 * COIN  # Mock value
            
            # Check outputs
            total_output_value = sum(out.value for out in transaction.outputs)
            
            # Check fee
            if total_input_value < total_output_value + transaction.fee:
                print("Insufficient funds")
                return False
            
            return True
            
        except Exception as e:
            print(f"Transaction validation error: {e}")
            return False
    
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