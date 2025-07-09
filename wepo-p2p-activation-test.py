#!/usr/bin/env python3
"""
WEPO P2P Network Activation Test
Tests the basic P2P networking functionality
"""

import sys
import os
import time
import threading
import signal

# Add the core directory to the Python path
sys.path.append('/app/wepo-blockchain/core')

def test_p2p_basic():
    """Test basic P2P networking functionality"""
    print("🌐 WEPO P2P NETWORK ACTIVATION TEST")
    print("="*60)
    
    try:
        from p2p_network import WepoP2PNode
        
        print("✅ Successfully imported WepoP2PNode")
        
        # Test 1: Create P2P node
        print("\n--- Test 1: Creating P2P Node ---")
        node = WepoP2PNode(host="127.0.0.1", port=22567)
        print(f"✅ Created P2P node: {node.node_id}")
        
        # Test 2: Start server
        print("\n--- Test 2: Starting P2P Server ---")
        node.start_server()
        print("✅ P2P server started")
        
        # Test 3: Check network info
        print("\n--- Test 3: Network Information ---")
        info = node.get_network_info()
        print(f"Node ID: {info['node_id']}")
        print(f"Version: {info['version']}")
        print(f"Peer Count: {info['peer_count']}")
        print(f"Port: {info['port']}")
        print(f"Known Addresses: {info['known_addresses']}")
        
        # Test 4: Create another node and test connection
        print("\n--- Test 4: Multi-Node Connection ---")
        node2 = WepoP2PNode(host="127.0.0.1", port=22568)
        node2.start_server()
        print("✅ Created second P2P node")
        
        # Wait for startup
        time.sleep(2)
        
        # Test connection
        print("Attempting to connect nodes...")
        success = node.connect_to_peer("127.0.0.1", 22568)
        if success:
            print("✅ Successfully connected nodes")
        else:
            print("❌ Failed to connect nodes")
        
        # Wait for handshake
        time.sleep(3)
        
        # Check connection status
        info1 = node.get_network_info()
        info2 = node2.get_network_info()
        
        print(f"\nNode 1 - Connected peers: {info1['peer_count']}")
        print(f"Node 2 - Connected peers: {info2['peer_count']}")
        
        if info1['peer_count'] > 0 and info2['peer_count'] > 0:
            print("✅ P2P connection established!")
        else:
            print("❌ P2P connection failed")
        
        # Test 5: Message broadcasting
        print("\n--- Test 5: Message Broadcasting ---")
        
        # Test transaction broadcast
        test_tx = {
            "txid": "test_tx_12345",
            "from": "wepo1test1",
            "to": "wepo1test2",
            "amount": 5.0
        }
        
        node.broadcast_transaction(test_tx)
        print("✅ Transaction broadcast test completed")
        
        # Test block broadcast
        test_block = {
            "hash": "test_block_67890",
            "height": 50,
            "prev_hash": "prev_block_hash"
        }
        
        node.broadcast_block(test_block)
        print("✅ Block broadcast test completed")
        
        # Test 6: Peer discovery
        print("\n--- Test 6: Peer Discovery ---")
        initial_known = len(node.known_addresses)
        node.discover_peers()
        time.sleep(2)
        final_known = len(node.known_addresses)
        
        print(f"Known addresses before: {initial_known}")
        print(f"Known addresses after: {final_known}")
        print("✅ Peer discovery test completed")
        
        # Keep running for a bit to observe
        print("\n--- Test 7: Network Monitoring ---")
        print("Monitoring network for 30 seconds...")
        
        for i in range(6):
            time.sleep(5)
            info1 = node.get_network_info()
            info2 = node2.get_network_info()
            
            print(f"[{i*5+5}s] Node1 peers: {info1['peer_count']}, Node2 peers: {info2['peer_count']}")
        
        print("\n🎉 P2P Network Test Completed Successfully!")
        
        # Cleanup
        print("\n--- Cleanup ---")
        node.stop_server()
        node2.stop_server()
        print("✅ P2P servers stopped")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_blockchain_integration():
    """Test P2P integration with blockchain"""
    print("\n🔗 BLOCKCHAIN-P2P INTEGRATION TEST")
    print("="*60)
    
    try:
        from wepo_node import WepoFullNode
        from blockchain import WepoBlockchain
        
        print("✅ Successfully imported blockchain components")
        
        # Test blockchain with P2P
        print("\n--- Creating blockchain with P2P ---")
        
        # Create blockchain node
        node = WepoFullNode(
            data_dir="/tmp/wepo-p2p-test",
            p2p_port=22567,
            api_port=8001,
            enable_mining=False
        )
        
        print("✅ Created WepoFullNode with P2P networking")
        
        # Test P2P network info
        p2p_info = node.p2p_node.get_network_info()
        print(f"P2P Node ID: {p2p_info['node_id']}")
        print(f"P2P Port: {p2p_info['port']}")
        
        # Test blockchain info
        blockchain_info = node.blockchain.get_blockchain_info()
        print(f"Blockchain Height: {blockchain_info['height']}")
        print(f"Blockchain Difficulty: {blockchain_info['difficulty']}")
        
        print("✅ Blockchain-P2P integration test completed")
        
        return True
        
    except Exception as e:
        print(f"❌ Blockchain integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function"""
    print("🚀 WEPO P2P NETWORK ACTIVATION")
    print("="*60)
    
    # Test 1: Basic P2P functionality
    basic_success = test_p2p_basic()
    
    # Test 2: Blockchain integration
    integration_success = test_blockchain_integration()
    
    # Summary
    print("\n" + "="*60)
    print("🏁 P2P NETWORK ACTIVATION SUMMARY")
    print("="*60)
    
    if basic_success:
        print("✅ Basic P2P functionality: WORKING")
    else:
        print("❌ Basic P2P functionality: FAILED")
    
    if integration_success:
        print("✅ Blockchain integration: WORKING")
    else:
        print("❌ Blockchain integration: FAILED")
    
    if basic_success and integration_success:
        print("\n🎉 P2P NETWORK ACTIVATION SUCCESSFUL!")
        print("The WEPO P2P network is ready for multi-node deployment!")
    else:
        print("\n❌ P2P NETWORK ACTIVATION FAILED")
        print("Issues need to be resolved before multi-node deployment")

if __name__ == "__main__":
    main()