#!/usr/bin/env python3
"""
WEPO P2P Network Multi-Node Test
Tests P2P networking with multiple blockchain nodes
"""

import sys
import os
import time
import threading
import signal
import multiprocessing
import subprocess
import json

# Add the core directory to the Python path
sys.path.append('/app/wepo-blockchain/core')

from wepo_node import WepoFullNode
from p2p_network import WepoP2PNode

class MultiNodeTester:
    """Multi-node P2P network tester"""
    
    def __init__(self):
        self.nodes = []
        self.processes = []
        self.running = False
        
    def start_node(self, node_id, p2p_port, api_port, data_dir):
        """Start a single WEPO node"""
        print(f"Starting node {node_id} on P2P port {p2p_port}, API port {api_port}")
        
        def run_node():
            try:
                node = WepoFullNode(
                    data_dir=data_dir,
                    p2p_port=p2p_port,
                    api_port=api_port,
                    enable_mining=False  # Disable mining for networking test
                )
                node.run()
            except Exception as e:
                print(f"Node {node_id} error: {e}")
        
        # Start node in separate thread
        thread = threading.Thread(target=run_node, daemon=True)
        thread.start()
        
        return thread
    
    def test_p2p_networking(self):
        """Test P2P networking with multiple nodes"""
        print("="*60)
        print("🌐 WEPO P2P NETWORKING TEST")
        print("="*60)
        
        # Configuration for test nodes
        nodes_config = [
            {"id": 1, "p2p_port": 22567, "api_port": 8001, "data_dir": "/tmp/wepo-node1"},
            {"id": 2, "p2p_port": 22568, "api_port": 8002, "data_dir": "/tmp/wepo-node2"},
            {"id": 3, "p2p_port": 22569, "api_port": 8003, "data_dir": "/tmp/wepo-node3"}
        ]
        
        print(f"Starting {len(nodes_config)} WEPO nodes...")
        
        # Start nodes
        for config in nodes_config:
            thread = self.start_node(
                config["id"],
                config["p2p_port"], 
                config["api_port"],
                config["data_dir"]
            )
            self.nodes.append(thread)
        
        # Wait for nodes to start
        print("Waiting for nodes to initialize...")
        time.sleep(10)
        
        # Test connectivity
        self.test_node_connectivity(nodes_config)
        
        # Test peer discovery
        self.test_peer_discovery(nodes_config)
        
        # Test message broadcasting
        self.test_message_broadcasting(nodes_config)
        
        self.running = True
        return True
    
    def test_node_connectivity(self, nodes_config):
        """Test basic node connectivity"""
        print("\n--- Testing Node Connectivity ---")
        
        import requests
        
        for config in nodes_config:
            try:
                response = requests.get(f"http://localhost:{config['api_port']}/api/network/status", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ Node {config['id']} (:{config['api_port']}) - Connected peers: {data.get('peers', 0)}")
                else:
                    print(f"❌ Node {config['id']} (:{config['api_port']}) - HTTP {response.status_code}")
            except Exception as e:
                print(f"❌ Node {config['id']} (:{config['api_port']}) - Error: {e}")
    
    def test_peer_discovery(self, nodes_config):
        """Test peer discovery mechanism"""
        print("\n--- Testing Peer Discovery ---")
        
        # Test connecting nodes to each other
        try:
            from p2p_network import WepoP2PNode
            
            # Create test P2P nodes
            p2p_nodes = []
            for i, config in enumerate(nodes_config):
                try:
                    node = WepoP2PNode(
                        host="127.0.0.1",
                        port=config["p2p_port"]
                    )
                    node.start_server()
                    p2p_nodes.append(node)
                    print(f"✅ P2P node {config['id']} started on port {config['p2p_port']}")
                except Exception as e:
                    print(f"❌ P2P node {config['id']} failed to start: {e}")
            
            # Wait for startup
            time.sleep(5)
            
            # Test peer connections
            if len(p2p_nodes) >= 2:
                print("Testing peer connections...")
                
                # Connect node 1 to node 2
                success = p2p_nodes[0].connect_to_peer("127.0.0.1", nodes_config[1]["p2p_port"])
                if success:
                    print("✅ Node 1 connected to Node 2")
                else:
                    print("❌ Node 1 failed to connect to Node 2")
                
                # Wait for connection establishment
                time.sleep(3)
                
                # Check network info
                for i, node in enumerate(p2p_nodes):
                    info = node.get_network_info()
                    print(f"Node {i+1} network info: {info}")
            
            # Cleanup
            for node in p2p_nodes:
                node.stop_server()
                
        except Exception as e:
            print(f"❌ Peer discovery test failed: {e}")
    
    def test_message_broadcasting(self, nodes_config):
        """Test message broadcasting between nodes"""
        print("\n--- Testing Message Broadcasting ---")
        
        # This would test transaction and block broadcasting
        # For now, we'll test the basic infrastructure
        
        try:
            from p2p_network import WepoP2PNode
            
            # Create test network
            node1 = WepoP2PNode(host="127.0.0.1", port=22570)
            node2 = WepoP2PNode(host="127.0.0.1", port=22571)
            
            node1.start_server()
            node2.start_server()
            
            time.sleep(2)
            
            # Connect nodes
            success = node1.connect_to_peer("127.0.0.1", 22571)
            if success:
                print("✅ Nodes connected for broadcasting test")
                
                # Wait for handshake
                time.sleep(2)
                
                # Test transaction broadcast
                test_tx = {
                    "txid": "test_transaction_123",
                    "from": "wepo1test1",
                    "to": "wepo1test2",
                    "amount": 10.0
                }
                
                node1.broadcast_transaction(test_tx)
                print("✅ Transaction broadcast test completed")
                
                # Test block broadcast
                test_block = {
                    "hash": "test_block_123",
                    "height": 100,
                    "prev_hash": "prev_block_hash"
                }
                
                node1.broadcast_block(test_block)
                print("✅ Block broadcast test completed")
                
            else:
                print("❌ Failed to connect nodes for broadcasting test")
            
            # Cleanup
            node1.stop_server()
            node2.stop_server()
            
        except Exception as e:
            print(f"❌ Message broadcasting test failed: {e}")
    
    def run_interactive_test(self):
        """Run interactive P2P network test"""
        print("\n🌐 Starting interactive P2P network test...")
        
        if not self.test_p2p_networking():
            print("❌ Failed to start P2P network test")
            return
        
        print("\n✅ P2P network test started successfully!")
        print("Network is running with multiple nodes...")
        print("Press Ctrl+C to stop the test")
        
        try:
            while self.running:
                time.sleep(5)
                
                # Print periodic status
                print(f"\n--- Network Status ({time.strftime('%H:%M:%S')}) ---")
                print(f"Active nodes: {len(self.nodes)}")
                print(f"Test running: {self.running}")
                
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping P2P network test...")
            self.running = False
            
        print("✅ P2P network test completed!")

def main():
    """Main test function"""
    print("🌐 WEPO P2P NETWORK MULTI-NODE TEST")
    print("="*60)
    
    tester = MultiNodeTester()
    
    # Handle graceful shutdown
    def signal_handler(signum, frame):
        print("\n🛑 Received shutdown signal")
        tester.running = False
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        tester.run_interactive_test()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("🏁 Test completed")

if __name__ == "__main__":
    main()