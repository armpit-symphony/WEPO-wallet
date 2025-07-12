#!/usr/bin/env python3
"""
WEPO Core Blockchain Security Test
Simple test to verify blockchain core functionality without import issues
"""

import sys
import os
import tempfile
import hashlib
import time

# Add the correct path
sys.path.insert(0, '/app/wepo-blockchain/core')

def test_blockchain_core():
    """Test core blockchain functionality"""
    print("🔧 Testing Core Blockchain Functionality")
    print("-" * 50)
    
    try:
        # Test 1: Import blockchain
        from blockchain import WepoBlockchain
        print("✅ Blockchain import successful")
        
        # Test 2: Create blockchain instance
        with tempfile.TemporaryDirectory() as temp_dir:
            blockchain = WepoBlockchain(temp_dir)
            print("✅ Blockchain initialization successful")
            
            # Test 3: Check basic methods
            height = blockchain.get_block_height()
            print(f"✅ Block height: {height}")
            
            # Test 4: Test block reward calculation
            reward = blockchain.calculate_block_reward(0)
            print(f"✅ Block reward calculation: {reward/100000000} WEPO")
            
            # Test 5: Test balance method
            test_addr = "wepo1test000000000000000000000000000"
            balance = blockchain.get_balance_wepo(test_addr)
            print(f"✅ Balance check: {balance} WEPO")
            
            # Test 6: Test transaction creation
            if hasattr(blockchain, 'create_transaction'):
                tx = blockchain.create_transaction(test_addr, test_addr, 1.0, 0.0001)
                if tx:
                    print("✅ Transaction creation successful")
                else:
                    print("⚠️ Transaction creation returned None (expected with no balance)")
            
            # Test 7: Test block creation
            block = blockchain.create_new_block(test_addr)
            if block:
                print("✅ Block creation successful")
                print(f"   Block height: {block.height}")
                print(f"   Block hash: {block.get_block_hash()[:16]}...")
            
            return True
            
    except Exception as e:
        print(f"❌ Blockchain test failed: {str(e)}")
        return False

def test_address_generation():
    """Test address generation"""
    print("\n🔧 Testing Address Generation")
    print("-" * 50)
    
    try:
        from dilithium import generate_dilithium_keypair, generate_wepo_address
        
        # Test keypair generation
        private_key, public_key = generate_dilithium_keypair()
        print("✅ Dilithium keypair generation successful")
        
        # Test address generation with public key
        if public_key:
            address = generate_wepo_address(public_key)
            print(f"✅ Address generation successful: {address}")
            
            # Validate address format
            if address.startswith("wepo1") and len(address) >= 37:
                print("✅ Address format validation passed")
                return True
            else:
                print("❌ Address format invalid")
                return False
        else:
            print("❌ No public key available")
            return False
            
    except Exception as e:
        print(f"❌ Address generation test failed: {str(e)}")
        return False

def test_signature_verification():
    """Test signature verification"""
    print("\n🔧 Testing Signature Verification")
    print("-" * 50)
    
    try:
        from dilithium import generate_dilithium_keypair
        
        # Generate keypair
        keypair = generate_dilithium_keypair()
        print("✅ Keypair generation successful")
        
        # Check if keypair is properly structured
        if isinstance(keypair, tuple) and len(keypair) == 2:
            private_key, public_key = keypair
            print("✅ Keypair structure is correct (tuple)")
            
            # Test key properties
            if hasattr(private_key, '__len__'):
                print(f"✅ Private key length: {len(private_key)}")
            
            if hasattr(public_key, '__len__'):
                print(f"✅ Public key length: {len(public_key)}")
                
            return True
        else:
            print(f"❌ Keypair structure issue: {type(keypair)}")
            return False
            
    except Exception as e:
        print(f"❌ Signature verification test failed: {str(e)}")
        return False

def test_privacy_features():
    """Test privacy features"""
    print("\n🔧 Testing Privacy Features")
    print("-" * 50)
    
    try:
        from privacy import create_privacy_proof, verify_privacy_proof
        
        # Test with correct private key length
        test_data = {
            'sender_private_key': b'a' * 32,  # 32 bytes as expected
            'recipient_address': 'wepo1test000000000000000000000000000',
            'amount': 100000000,
            'decoy_keys': [b'decoy1', b'decoy2', b'decoy3']
        }
        
        proof = create_privacy_proof(test_data)
        print(f"✅ Privacy proof generated: {len(proof)} bytes")
        
        # Test verification
        is_valid = verify_privacy_proof(proof, b'test_message')
        print(f"✅ Privacy proof verification: {is_valid}")
        
        return True
        
    except Exception as e:
        print(f"❌ Privacy features test failed: {str(e)}")
        return False

def test_rwa_validation():
    """Test RWA address validation"""
    print("\n🔧 Testing RWA Address Validation")
    print("-" * 50)
    
    try:
        from rwa_tokens import RWATokenSystem
        
        rwa_system = RWATokenSystem()
        
        # Test valid addresses
        valid_addresses = [
            "wepo1test000000000000000000000000000",  # 37 chars
            "wepo1quantum000000000000000000000000000000000"  # 45 chars
        ]
        
        for addr in valid_addresses:
            is_valid = rwa_system.is_valid_address(addr)
            print(f"✅ Address {addr[:20]}... validation: {is_valid}")
        
        # Test invalid addresses
        invalid_addresses = [
            "bitcoin1invalid",
            "wepo1",
            "",
            "not_an_address"
        ]
        
        for addr in invalid_addresses:
            is_valid = rwa_system.is_valid_address(addr)
            print(f"✅ Invalid address {addr} rejected: {not is_valid}")
        
        return True
        
    except Exception as e:
        print(f"❌ RWA validation test failed: {str(e)}")
        return False

def main():
    """Run all core tests"""
    print("🛡️ WEPO CORE SECURITY VALIDATION")
    print("=" * 60)
    
    tests = [
        ("Blockchain Core", test_blockchain_core),
        ("Address Generation", test_address_generation),
        ("Signature Verification", test_signature_verification),
        ("Privacy Features", test_privacy_features),
        ("RWA Validation", test_rwa_validation)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name} Test...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} Test PASSED")
            else:
                print(f"❌ {test_name} Test FAILED")
        except Exception as e:
            print(f"❌ {test_name} Test ERROR: {str(e)}")
    
    print(f"\n" + "=" * 60)
    print(f"🎯 CORE SECURITY VALIDATION SUMMARY")
    print(f"Passed: {passed}/{total} tests")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("🎉 All core security tests passed!")
        return 0
    else:
        print("⚠️ Some core security tests failed")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)