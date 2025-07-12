#!/usr/bin/env python3
"""
WEPO Community Genesis Block Implementation
Technical framework for fair launch with community-mined genesis
"""

import hashlib
import time
import json
import struct
import socket
import threading
import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

@dataclass
class GenesisConfiguration:
    """Configuration for WEPO genesis block"""
    network_magic: bytes = b"WEPO"
    version: int = 1
    genesis_message: str = "WEPO: Financial Freedom Through Privacy - Community Launch"
    initial_difficulty: int = 0x1d00ffff  # Bitcoin's initial difficulty
    block_reward: int = 400 * 100000000  # 400 WEPO in satoshis
    halving_interval: int = 131400  # 6 months in blocks
    
    # Launch coordination (configurable)
    launch_timestamp: Optional[int] = None  # UTC timestamp - TBD
    preparation_hours: int = 24
    announcement_days: int = 30
    
    # Network parameters
    pos_activation_height: int = 78840
    min_stake_amount: int = 1000 * 100000000
    masternode_collateral: int = 10000 * 100000000
    
    # Fair launch guarantees
    pre_mine: int = 0
    developer_allocation: int = 0
    founder_rewards: int = 0
    ico_coins: int = 0

class GenesisBlockManager:
    """Manages community-mined genesis block creation"""
    
    def __init__(self, config: GenesisConfiguration):
        self.config = config
        self.genesis_template = None
        self.mining_active = False
        self.genesis_found = False
        self.winning_block = None
        
        # Mining coordination
        self.miners = {}  # Connected miners
        self.launch_coordinators = []  # Launch coordination nodes
    
    def create_genesis_template(self, launch_timestamp: int) -> dict:
        """Create genesis block template for community mining"""
        
        # Coinbase transaction (block reward to winner)
        coinbase_tx = {
            "version": 1,
            "inputs": [{
                "prev_hash": "0" * 64,
                "prev_index": 0xffffffff,
                "script_sig": self._create_coinbase_script(),
                "sequence": 0xffffffff
            }],
            "outputs": [{
                "value": self.config.block_reward,
                "script_pubkey": None  # Will be set by winning miner
            }],
            "lock_time": 0
        }
        
        # Genesis block template
        genesis_template = {
            "version": self.config.version,
            "prev_hash": "0" * 64,  # Genesis has no previous block
            "merkle_root": self._calculate_merkle_root([coinbase_tx]),
            "timestamp": launch_timestamp,
            "difficulty": self.config.initial_difficulty,
            "nonce": 0,  # To be found by miners
            "coinbase": coinbase_tx,
            "transactions": [coinbase_tx]
        }
        
        self.genesis_template = genesis_template
        return genesis_template
    
    def _create_coinbase_script(self) -> bytes:
        """Create coinbase script with genesis message"""
        message = self.config.genesis_message.encode()
        height_bytes = struct.pack('<I', 0)  # Block height 0
        timestamp_bytes = struct.pack('<I', int(time.time()))
        
        # Combine height, timestamp, and message
        script = height_bytes + timestamp_bytes + bytes([len(message)]) + message
        return script
    
    def _calculate_merkle_root(self, transactions: List[dict]) -> str:
        """Calculate merkle root of transactions"""
        if not transactions:
            return "0" * 64
        
        # For genesis block with single coinbase transaction
        tx_hash = self._hash_transaction(transactions[0])
        return tx_hash
    
    def _hash_transaction(self, tx: dict) -> str:
        """Hash a transaction"""
        tx_data = json.dumps(tx, sort_keys=True).encode()
        return hashlib.sha256(hashlib.sha256(tx_data).digest()).digest().hex()
    
    def _hash_block_header(self, block: dict) -> str:
        """Hash block header for mining"""
        header_data = struct.pack('<I', block['version'])
        header_data += bytes.fromhex(block['prev_hash'])
        header_data += bytes.fromhex(block['merkle_root'])
        header_data += struct.pack('<I', block['timestamp'])
        header_data += struct.pack('<I', block['difficulty'])
        header_data += struct.pack('<I', block['nonce'])
        
        return hashlib.sha256(hashlib.sha256(header_data).digest()).digest().hex()
    
    def validate_genesis_block(self, block: dict) -> bool:
        """Validate a proposed genesis block"""
        try:
            # Check basic structure
            required_fields = ['version', 'prev_hash', 'merkle_root', 'timestamp', 'difficulty', 'nonce']
            if not all(field in block for field in required_fields):
                return False
            
            # Check genesis-specific values
            if block['version'] != self.config.version:
                return False
            if block['prev_hash'] != "0" * 64:
                return False
            if block['difficulty'] != self.config.initial_difficulty:
                return False
            
            # Check proof of work
            block_hash = self._hash_block_header(block)
            target = self._difficulty_to_target(block['difficulty'])
            
            if int(block_hash, 16) > target:
                return False  # Insufficient proof of work
            
            # Check coinbase transaction
            if not self._validate_coinbase(block.get('coinbase')):
                return False
            
            return True
            
        except Exception as e:
            print(f"Genesis validation error: {e}")
            return False
    
    def _difficulty_to_target(self, difficulty: int) -> int:
        """Convert difficulty bits to target"""
        exp = difficulty >> 24
        mantissa = difficulty & 0xffffff
        target = mantissa * (2 ** (8 * (exp - 3)))
        return target
    
    def _validate_coinbase(self, coinbase: dict) -> bool:
        """Validate coinbase transaction"""
        if not coinbase:
            return False
        
        # Check reward amount
        if len(coinbase['outputs']) != 1:
            return False
        
        if coinbase['outputs'][0]['value'] != self.config.block_reward:
            return False
        
        return True
    
    def start_genesis_mining_coordination(self, launch_timestamp: int):
        """Start coordinating genesis block mining"""
        print(f"🚀 Starting WEPO Genesis Block Mining Coordination")
        print(f"   Launch Time: {datetime.fromtimestamp(launch_timestamp, timezone.utc)}")
        
        # Create genesis template
        self.create_genesis_template(launch_timestamp)
        
        # Wait for launch time
        current_time = int(time.time())
        if launch_timestamp > current_time:
            wait_time = launch_timestamp - current_time
            print(f"   Waiting {wait_time} seconds until launch...")
            time.sleep(wait_time)
        
        # Activate mining
        self.mining_active = True
        print("⛏️ GENESIS MINING ACTIVATED!")
        print("   Community miners can now compete for genesis block!")
        
        # Start monitoring for valid genesis blocks
        self._monitor_genesis_submissions()
    
    def _monitor_genesis_submissions(self):
        """Monitor and validate genesis block submissions"""
        print("👀 Monitoring genesis block submissions...")
        
        while self.mining_active and not self.genesis_found:
            # In a real implementation, this would listen for network submissions
            # For now, we simulate the process
            time.sleep(1)
            
            # Simulate checking for submissions
            # Real implementation would validate submitted blocks
        
        if self.genesis_found:
            print("🎉 VALID GENESIS BLOCK FOUND!")
            print(f"   Winner: {self.winning_block.get('miner_address', 'Unknown')}")
            print(f"   Block Hash: {self._hash_block_header(self.winning_block)}")
    
    def submit_genesis_block(self, block: dict, miner_address: str) -> bool:
        """Submit a genesis block candidate"""
        if not self.mining_active or self.genesis_found:
            return False
        
        # Set miner address in coinbase output
        block['coinbase']['outputs'][0]['script_pubkey'] = miner_address.encode()
        
        # Validate the block
        if self.validate_genesis_block(block):
            self.genesis_found = True
            self.mining_active = False
            self.winning_block = block
            
            print(f"🏆 GENESIS BLOCK ACCEPTED!")
            print(f"   Miner: {miner_address}")
            print(f"   Block Hash: {self._hash_block_header(block)}")
            print(f"   Reward: {self.config.block_reward / 100000000} WEPO")
            
            return True
        
        return False

class CommunityMiningServer:
    """Server to coordinate community mining"""
    
    def __init__(self, genesis_manager: GenesisBlockManager, port: int = 8888):
        self.genesis_manager = genesis_manager
        self.port = port
        self.server_socket = None
        self.running = False
        self.connected_miners = {}
    
    def start_server(self):
        """Start mining coordination server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(100)  # Allow many miners
            
            self.running = True
            print(f"🌐 Mining coordination server started on port {self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    threading.Thread(
                        target=self._handle_miner,
                        args=(client_socket, addr),
                        daemon=True
                    ).start()
                except:
                    if self.running:
                        time.sleep(1)
        
        except Exception as e:
            print(f"❌ Mining server error: {e}")
    
    def _handle_miner(self, client_socket: socket.socket, addr: tuple):
        """Handle individual miner connection"""
        miner_id = f"{addr[0]}:{addr[1]}"
        self.connected_miners[miner_id] = {
            'socket': client_socket,
            'address': addr,
            'connected_time': time.time()
        }
        
        print(f"⛏️ Miner connected: {miner_id}")
        
        try:
            while self.running:
                # Send genesis template to miner
                if self.genesis_manager.genesis_template:
                    template_data = json.dumps(self.genesis_manager.genesis_template).encode()
                    message = b'TEMPLATE' + struct.pack('I', len(template_data)) + template_data
                    client_socket.send(message)
                
                # Listen for block submissions
                data = client_socket.recv(4096)
                if not data:
                    break
                
                if data.startswith(b'SUBMIT'):
                    self._handle_block_submission(data[6:], miner_id)
                
                time.sleep(1)
        
        except Exception as e:
            print(f"⚠️ Miner {miner_id} error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            if miner_id in self.connected_miners:
                del self.connected_miners[miner_id]
            
            print(f"⛏️ Miner disconnected: {miner_id}")
    
    def _handle_block_submission(self, data: bytes, miner_id: str):
        """Handle genesis block submission from miner"""
        try:
            block_data = json.loads(data.decode())
            miner_address = block_data.get('miner_address', 'unknown')
            
            # Submit to genesis manager
            success = self.genesis_manager.submit_genesis_block(block_data, miner_address)
            
            if success:
                print(f"🏆 GENESIS BLOCK ACCEPTED FROM {miner_id}")
                # Notify all miners that genesis was found
                self._broadcast_genesis_found()
        
        except Exception as e:
            print(f"❌ Block submission error from {miner_id}: {e}")
    
    def _broadcast_genesis_found(self):
        """Broadcast to all miners that genesis was found"""
        message = b'GENESIS_FOUND'
        
        for miner_id, miner_info in self.connected_miners.items():
            try:
                miner_info['socket'].send(message)
            except:
                pass
    
    def stop_server(self):
        """Stop mining coordination server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("🛑 Mining coordination server stopped")
    
    def get_miner_stats(self) -> dict:
        """Get mining statistics"""
        return {
            'connected_miners': len(self.connected_miners),
            'miners': list(self.connected_miners.keys()),
            'genesis_found': self.genesis_manager.genesis_found,
            'mining_active': self.genesis_manager.mining_active
        }

class GenesisLaunchCoordinator:
    """Coordinates the entire genesis launch process"""
    
    def __init__(self):
        self.config = GenesisConfiguration()
        self.genesis_manager = GenesisBlockManager(self.config)
        self.mining_server = CommunityMiningServer(self.genesis_manager)
        self.launch_status = "preparing"
        
    def set_launch_time(self, launch_timestamp: int):
        """Set the community launch time"""
        self.config.launch_timestamp = launch_timestamp
        launch_datetime = datetime.fromtimestamp(launch_timestamp, timezone.utc)
        
        print(f"📅 WEPO Community Launch Scheduled")
        print(f"   UTC Time: {launch_datetime.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        print(f"   Timestamp: {launch_timestamp}")
        
        # Calculate preparation milestones
        current_time = int(time.time())
        time_until_launch = launch_timestamp - current_time
        
        if time_until_launch > 0:
            days_until = time_until_launch // 86400
            hours_until = (time_until_launch % 86400) // 3600
            
            print(f"   Time Remaining: {days_until} days, {hours_until} hours")
            
            # Set preparation schedule
            if time_until_launch >= 30 * 86400:  # More than 30 days
                print("📋 Preparation Phase: Long-term planning")
            elif time_until_launch >= 7 * 86400:  # 7-30 days
                print("📋 Preparation Phase: Community announcement")
            elif time_until_launch >= 86400:  # 1-7 days
                print("📋 Preparation Phase: Final preparations")
            else:  # Less than 24 hours
                print("📋 Preparation Phase: Launch countdown")
        else:
            print("⚠️ Launch time is in the past!")
    
    def start_launch_preparation(self):
        """Start launch preparation process"""
        print("🚀 Starting WEPO Genesis Launch Preparation")
        print("=" * 60)
        
        self.launch_status = "preparing"
        
        # Check configuration
        self._validate_launch_configuration()
        
        # Start mining coordination server
        threading.Thread(target=self.mining_server.start_server, daemon=True).start()
        
        # Wait for launch time
        if self.config.launch_timestamp:
            self._wait_for_launch_time()
        else:
            print("⏸️ Launch time not set. Waiting for configuration...")
    
    def _validate_launch_configuration(self):
        """Validate launch configuration"""
        print("✅ Validating launch configuration...")
        
        validations = [
            (self.config.pre_mine == 0, "Zero pre-mine verified"),
            (self.config.developer_allocation == 0, "Zero developer allocation verified"),
            (self.config.founder_rewards == 0, "Zero founder rewards verified"),
            (self.config.ico_coins == 0, "Zero ICO coins verified"),
            (self.config.block_reward > 0, "Valid block reward set"),
            (self.config.initial_difficulty > 0, "Valid initial difficulty set")
        ]
        
        for validation, message in validations:
            status = "✅" if validation else "❌"
            print(f"   {status} {message}")
        
        all_valid = all(v[0] for v in validations)
        
        if all_valid:
            print("✅ Launch configuration validated - Fair launch confirmed!")
        else:
            print("❌ Launch configuration invalid!")
            self.launch_status = "invalid"
    
    def _wait_for_launch_time(self):
        """Wait for the scheduled launch time"""
        if not self.config.launch_timestamp:
            return
        
        current_time = int(time.time())
        launch_time = self.config.launch_timestamp
        
        if launch_time <= current_time:
            print("🚀 Launch time reached! Starting genesis mining...")
            self._start_genesis_mining()
        else:
            wait_time = launch_time - current_time
            print(f"⏳ Waiting {wait_time} seconds for launch time...")
            
            # Show countdown updates
            while current_time < launch_time:
                remaining = launch_time - current_time
                
                if remaining % 3600 == 0:  # Every hour
                    hours_left = remaining // 3600
                    print(f"⏳ {hours_left} hours until WEPO genesis launch...")
                elif remaining % 60 == 0 and remaining <= 600:  # Last 10 minutes
                    minutes_left = remaining // 60
                    print(f"⏳ {minutes_left} minutes until WEPO genesis launch...")
                elif remaining <= 10:  # Last 10 seconds
                    print(f"⏳ {remaining} seconds...")
                
                time.sleep(1)
                current_time = int(time.time())
            
            print("🚀 LAUNCH TIME! Starting genesis mining...")
            self._start_genesis_mining()
    
    def _start_genesis_mining(self):
        """Start the genesis mining process"""
        self.launch_status = "mining"
        
        print("🚀 WEPO GENESIS MINING BEGINS!")
        print("=" * 60)
        print("⛏️ Community miners can now compete for genesis block #0")
        print(f"💰 Reward: {self.config.block_reward / 100000000} WEPO")
        print(f"🎯 Difficulty: {hex(self.config.initial_difficulty)}")
        print("=" * 60)
        
        # Start genesis mining coordination
        self.genesis_manager.start_genesis_mining_coordination(self.config.launch_timestamp)
        
        # Monitor until genesis is found
        while not self.genesis_manager.genesis_found:
            stats = self.mining_server.get_miner_stats()
            print(f"📊 Mining Status: {stats['connected_miners']} miners connected")
            time.sleep(10)
        
        self.launch_status = "completed"
        print("🎉 GENESIS BLOCK MINED! WEPO BLOCKCHAIN IS LIVE!")
    
    def get_launch_status(self) -> dict:
        """Get current launch status"""
        current_time = int(time.time())
        
        status = {
            "status": self.launch_status,
            "current_time": current_time,
            "launch_timestamp": self.config.launch_timestamp,
            "genesis_found": self.genesis_manager.genesis_found,
            "mining_active": self.genesis_manager.mining_active,
            "configuration": {
                "block_reward": self.config.block_reward / 100000000,
                "initial_difficulty": hex(self.config.initial_difficulty),
                "fair_launch": {
                    "pre_mine": self.config.pre_mine,
                    "developer_allocation": self.config.developer_allocation,
                    "founder_rewards": self.config.founder_rewards,
                    "ico_coins": self.config.ico_coins
                }
            }
        }
        
        if self.config.launch_timestamp:
            time_until = self.config.launch_timestamp - current_time
            status["time_until_launch"] = max(0, time_until)
            status["launch_datetime"] = datetime.fromtimestamp(
                self.config.launch_timestamp, timezone.utc
            ).isoformat()
        
        if hasattr(self.mining_server, 'get_miner_stats'):
            status["mining_stats"] = self.mining_server.get_miner_stats()
        
        return status

def main():
    """Test the genesis launch coordination system"""
    print("🚀 WEPO COMMUNITY GENESIS LAUNCH COORDINATOR")
    print("=" * 80)
    print("Technical framework for fair launch with community-mined genesis")
    print("=" * 80)
    
    # Create launch coordinator
    coordinator = GenesisLaunchCoordinator()
    
    # Example: Set launch time (5 minutes from now for testing)
    # In production, this would be set to the actual launch date
    test_launch_time = int(time.time()) + 300  # 5 minutes from now
    coordinator.set_launch_time(test_launch_time)
    
    # Show status
    status = coordinator.get_launch_status()
    print("📊 LAUNCH STATUS:")
    print(f"   Status: {status['status']}")
    print(f"   Launch Time: {status.get('launch_datetime', 'Not set')}")
    print(f"   Time Until Launch: {status.get('time_until_launch', 0)} seconds")
    
    print("\n✅ Genesis launch framework ready!")
    print("🎯 Set your launch date and time when ready!")
    
    return coordinator

if __name__ == "__main__":
    coordinator = main()