#!/usr/bin/env python3
"""
WEPO Blockchain Test Suite
Comprehensive testing of blockchain functionality
"""

import sys
import os
import time
import requests
import json
import threading
from subprocess import Popen, PIPE
import signal

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.blockchain import WepoBlockchain, Transaction, TransactionInput, TransactionOutput
from core.p2p_network import WepoP2PNode
from miner.wepo_miner import WepoArgon2Miner

class WepoBlockchainTester:
    """Comprehensive WEPO blockchain tester"""
    
    def __init__(self):
        self.test_data_dir = "/tmp/wepo_test"
        self.processes = []
        self.test_results = {
            'total': 0,
            'passed': 0,
            'failed': 0,
            'tests': []
        }
    
    def log_test(self, name: str, passed: bool, details: str = ""):
        """Log test result"""
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}")
        if details:
            print(f"        {details}")
        
        self.test_results['total'] += 1
        if passed:
            self.test_results['passed'] += 1
        else:
            self.test_results['failed'] += 1
        
        self.test_results['tests'].append({
            'name': name,
            'passed': passed,
            'details': details
        })
    
    def cleanup(self):
        """Clean up test environment"""
        print("\nCleaning up test environment...")
        
        # Kill all test processes
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
        
        # Clean up test data
        import shutil
        if os.path.exists(self.test_data_dir):
            shutil.rmtree(self.test_data_dir)
    
    def test_blockchain_core(self):
        """Test core blockchain functionality"""
        print("\n=== Testing Blockchain Core ===")
        
        try:
            # Initialize blockchain
            blockchain = WepoBlockchain(self.test_data_dir)
            self.log_test("Blockchain initialization", True, f"Height: {blockchain.get_block_height()}")
            
            # Test genesis block
            genesis = blockchain.get_latest_block()
            if genesis and genesis.height == 0:
                self.log_test("Genesis block creation", True, f"Hash: {genesis.get_block_hash()[:16]}...")
            else:
                self.log_test("Genesis block creation", False, "Genesis block not found")
            
            # Test block creation
            new_block = blockchain.create_new_block("wepo1test000000000000000000000000000")
            expected_height = blockchain.get_block_height() + 1
            if new_block.height == expected_height:
                self.log_test("Block creation", True, f"Height: {new_block.height}")
            else:
                self.log_test("Block creation", False, f"Wrong height: {new_block.height}")
            
            # Test reward calculation
            reward = blockchain.calculate_block_reward(1)
            expected_reward = 121.6 * 100000000  # Year 1 reward
            if reward == expected_reward:
                self.log_test("Reward calculation", True, f"Reward: {reward / 100000000} WEPO")
            else:
                self.log_test("Reward calculation", False, f"Wrong reward: {reward}")
            
            # Test blockchain info
            info = blockchain.get_blockchain_info()
            if isinstance(info, dict) and 'height' in info:
                self.log_test("Blockchain info", True, f"Info keys: {list(info.keys())}")
            else:
                self.log_test("Blockchain info", False, "Invalid info format")
                
        except Exception as e:
            self.log_test("Blockchain core", False, f"Exception: {e}")
    
    def test_mining(self):
        """Test mining functionality"""
        print("\n=== Testing Mining ===")
        
        try:
            # Initialize miner
            miner = WepoArgon2Miner(threads=1, intensity=1024)  # Low intensity for testing
            self.log_test("Miner initialization", True, "Argon2 miner created")
            
            # Test difficulty calculation
            test_hash = "000abc123def456789"
            difficulty = miner.calculate_difficulty(test_hash)
            if difficulty == 3:  # Should count 3 leading zeros
                self.log_test("Difficulty calculation", True, f"Difficulty: {difficulty}")
            else:
                self.log_test("Difficulty calculation", False, f"Wrong difficulty: {difficulty}")
            
            # Test target checking
            easy_target = 2
            if miner.check_target(test_hash, easy_target):
                self.log_test("Target checking", True, "Easy target met")
            else:
                self.log_test("Target checking", False, "Easy target not met")
            
        except Exception as e:
            self.log_test("Mining", False, f"Exception: {e}")
    
    def test_p2p_network(self):
        """Test P2P networking"""
        print("\n=== Testing P2P Network ===")
        
        try:
            # Create P2P node
            node = WepoP2PNode(port=22570)  # Use different port for testing
            self.log_test("P2P node creation", True, f"Node ID: {node.node_id}")
            
            # Test message creation
            test_msg = node.create_message('ping', b'test_payload')
            if test_msg.startswith(b'WEPO'):
                self.log_test("Message creation", True, f"Message length: {len(test_msg)}")
            else:
                self.log_test("Message creation", False, "Invalid message format")
            
            # Test message parsing
            parsed = node.parse_message(test_msg)
            if parsed and parsed.command == 'ping':
                self.log_test("Message parsing", True, f"Command: {parsed.command}")
            else:
                self.log_test("Message parsing", False, "Message parsing failed")
            
            # Test network info
            info = node.get_network_info()
            if isinstance(info, dict) and 'node_id' in info:
                self.log_test("Network info", True, f"Peer count: {info['peer_count']}")
            else:
                self.log_test("Network info", False, "Invalid network info")
                
        except Exception as e:
            self.log_test("P2P network", False, f"Exception: {e}")
    
    def test_transactions(self):
        """Test transaction functionality"""
        print("\n=== Testing Transactions ===")
        
        try:
            # Create test transaction
            tx = Transaction(
                version=1,
                inputs=[TransactionInput("test_txid", 0, b"test_script")],
                outputs=[TransactionOutput(100000000, b"test_script", "wepo1test")],
                lock_time=0
            )
            
            # Test transaction ID calculation
            txid = tx.calculate_txid()
            if len(txid) == 64:  # SHA256 hash length
                self.log_test("Transaction ID", True, f"TXID: {txid[:16]}...")
            else:
                self.log_test("Transaction ID", False, f"Invalid TXID length: {len(txid)}")
            
            # Test coinbase detection
            coinbase_tx = Transaction(
                version=1,
                inputs=[TransactionInput("0" * 64, 0xffffffff, b"coinbase")],
                outputs=[TransactionOutput(100000000, b"test_script", "wepo1test")],
                lock_time=0
            )
            
            if coinbase_tx.is_coinbase():
                self.log_test("Coinbase detection", True, "Coinbase transaction detected")
            else:
                self.log_test("Coinbase detection", False, "Coinbase detection failed")
                
        except Exception as e:
            self.log_test("Transactions", False, f"Exception: {e}")
    
    def test_integration(self):
        """Test integration between components"""
        print("\n=== Testing Integration ===")
        
        try:
            # Start a test node in the background
            print("Starting test node...")
            node_proc = Popen([
                sys.executable, "core/wepo_node.py",
                "--data-dir", f"{self.test_data_dir}/integration",
                "--p2p-port", "22571",
                "--api-port", "8101",
                "--no-mining"
            ], stdout=PIPE, stderr=PIPE)
            
            self.processes.append(node_proc)
            time.sleep(5)  # Wait for node to start
            
            # Test API connectivity
            try:
                response = requests.get("http://localhost:8101/api/network/status", timeout=5)
                if response.status_code == 200:
                    self.log_test("API connectivity", True, f"Status: {response.status_code}")
                    
                    # Test blockchain info API
                    data = response.json()
                    if 'height' in data:
                        self.log_test("API data format", True, f"Height: {data['height']}")
                    else:
                        self.log_test("API data format", False, "Missing height field")
                else:
                    self.log_test("API connectivity", False, f"Status: {response.status_code}")
                    
            except requests.RequestException as e:
                self.log_test("API connectivity", False, f"Connection failed: {e}")
            
            # Test mining info API
            try:
                response = requests.get("http://localhost:8101/api/mining/info", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if 'current_reward' in data:
                        self.log_test("Mining API", True, f"Reward: {data['current_reward']}")
                    else:
                        self.log_test("Mining API", False, "Missing reward field")
                else:
                    self.log_test("Mining API", False, f"Status: {response.status_code}")
                    
            except requests.RequestException as e:
                self.log_test("Mining API", False, f"Request failed: {e}")
                
        except Exception as e:
            self.log_test("Integration", False, f"Exception: {e}")
    
    def test_wallet_daemon(self):
        """Test wallet daemon functionality"""
        print("\n=== Testing Wallet Daemon ===")
        
        try:
            # Start wallet daemon
            print("Starting wallet daemon...")
            wallet_proc = Popen([
                sys.executable, "wallet-daemon/wepo_walletd.py",
                "--node-host", "localhost",
                "--node-port", "8101",
                "--port", "8102"
            ], stdout=PIPE, stderr=PIPE)
            
            self.processes.append(wallet_proc)
            time.sleep(3)  # Wait for wallet daemon to start
            
            # Test wallet daemon API
            try:
                response = requests.get("http://localhost:8102/api/", timeout=5)
                if response.status_code == 200:
                    self.log_test("Wallet daemon API", True, "Daemon responding")
                    
                    # Test wallet creation
                    wallet_data = {
                        'username': 'test_user',
                        'address': 'wepo1test000000000000000000000000000',
                        'encrypted_private_key': 'test_encrypted_key'
                    }
                    
                    response = requests.post("http://localhost:8102/api/wallet/create", 
                                           json=wallet_data, timeout=5)
                    if response.status_code == 200:
                        self.log_test("Wallet creation API", True, "Wallet created")
                    else:
                        self.log_test("Wallet creation API", False, f"Status: {response.status_code}")
                        
                else:
                    self.log_test("Wallet daemon API", False, f"Status: {response.status_code}")
                    
            except requests.RequestException as e:
                self.log_test("Wallet daemon API", False, f"Connection failed: {e}")
                
        except Exception as e:
            self.log_test("Wallet daemon", False, f"Exception: {e}")
    
    def run_all_tests(self):
        """Run all tests"""
        print("🚀 WEPO Blockchain Test Suite")
        print("=" * 50)
        
        start_time = time.time()
        
        try:
            # Core tests
            self.test_blockchain_core()
            self.test_mining()
            self.test_p2p_network()
            self.test_transactions()
            
            # Integration tests
            self.test_integration()
            self.test_wallet_daemon()
            
        finally:
            self.cleanup()
        
        # Print results
        end_time = time.time()
        duration = end_time - start_time
        
        print("\n" + "=" * 50)
        print("📊 Test Results Summary")
        print("=" * 50)
        print(f"Total tests:    {self.test_results['total']}")
        print(f"Passed:         {self.test_results['passed']}")
        print(f"Failed:         {self.test_results['failed']}")
        print(f"Success rate:   {(self.test_results['passed'] / self.test_results['total'] * 100):.1f}%")
        print(f"Duration:       {duration:.2f} seconds")
        
        if self.test_results['failed'] > 0:
            print(f"\n❌ {self.test_results['failed']} tests failed:")
            for test in self.test_results['tests']:
                if not test['passed']:
                    print(f"  - {test['name']}: {test['details']}")
        else:
            print("\n✅ All tests passed!")
        
        return self.test_results['failed'] == 0

def main():
    """Main function"""
    print("WEPO Blockchain Test Suite")
    print("Testing revolutionary cryptocurrency implementation")
    print()
    
    tester = WepoBlockchainTester()
    
    def signal_handler(signum, frame):
        print("\nTest interrupted by user")
        tester.cleanup()
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\nTest suite failed with exception: {e}")
        tester.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()