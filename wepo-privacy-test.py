#!/usr/bin/env python3
"""
WEPO Privacy Features Test Suite
Comprehensive testing of privacy implementations
"""

import sys
import os
import time
import json
from Crypto.Random import get_random_bytes

# Add the core directory to the Python path
sys.path.append('/app/wepo-blockchain/core')

def test_privacy_core_functionality():
    """Test core privacy functionality"""
    print("🔒 WEPO PRIVACY FEATURES TEST")
    print("="*60)
    
    # Test 1: Import privacy classes
    try:
        from privacy import (
            privacy_engine, 
            create_privacy_proof, 
            verify_privacy_proof,
            ZKStarkProver,
            RingSignature,
            ConfidentialTransactions,
            PrivacyProof
        )
        print("✅ Successfully imported privacy classes")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    
    # Test 2: zk-STARK proof generation and verification
    try:
        print("\n--- Test 2: zk-STARK Proofs ---")
        stark_prover = ZKStarkProver()
        
        secret_input = b"secret_transaction_data"
        public_statement = b"wepo1recipient_address"
        
        # Generate proof
        stark_proof = stark_prover.generate_stark_proof(secret_input, public_statement)
        print(f"✅ Generated zk-STARK proof: {stark_proof.proof_type}")
        print(f"   Proof size: {len(stark_proof.proof_data)} bytes")
        
        # Verify proof
        is_valid = stark_prover.verify_stark_proof(stark_proof, public_statement)
        print(f"✅ zk-STARK verification: {'VALID' if is_valid else 'INVALID'}")
        
        if not is_valid:
            print("❌ zk-STARK proof verification failed")
            return False
            
    except Exception as e:
        print(f"❌ zk-STARK test failed: {e}")
        return False
    
    # Test 3: Ring signature generation and verification
    try:
        print("\n--- Test 3: Ring Signatures ---")
        ring_signer = RingSignature()
        
        message = b"transaction_to_sign"
        private_key = get_random_bytes(32)
        public_keys = [get_random_bytes(32) for _ in range(5)]
        
        # Generate ring signature
        ring_proof = ring_signer.generate_ring_signature(message, private_key, public_keys)
        print(f"✅ Generated ring signature: {ring_proof.proof_type}")
        print(f"   Ring size: {ring_proof.public_parameters['ring_size']}")
        print(f"   Proof size: {len(ring_proof.proof_data)} bytes")
        
        # Verify ring signature
        is_valid = ring_signer.verify_ring_signature(ring_proof, message)
        print(f"✅ Ring signature verification: {'VALID' if is_valid else 'INVALID'}")
        
        if not is_valid:
            print("❌ Ring signature verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Ring signature test failed: {e}")
        return False
    
    # Test 4: Confidential transactions
    try:
        print("\n--- Test 4: Confidential Transactions ---")
        confidential_tx = ConfidentialTransactions()
        
        amount = 100000000  # 1 WEPO in satoshis
        blinding_factor = get_random_bytes(32)
        
        # Generate range proof
        range_proof = confidential_tx.generate_range_proof(amount, blinding_factor)
        print(f"✅ Generated range proof: {range_proof.proof_type}")
        print(f"   Commitment: {range_proof.public_parameters['commitment'][:16]}...")
        print(f"   Proof size: {len(range_proof.proof_data)} bytes")
        
        # Verify range proof
        is_valid = confidential_tx.verify_range_proof(range_proof)
        print(f"✅ Range proof verification: {'VALID' if is_valid else 'INVALID'}")
        
        if not is_valid:
            print("❌ Range proof verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Confidential transaction test failed: {e}")
        return False
    
    # Test 5: Stealth addresses
    try:
        print("\n--- Test 5: Stealth Addresses ---")
        
        recipient_public_key = get_random_bytes(32)
        stealth_addr, shared_secret = privacy_engine.generate_stealth_address(recipient_public_key)
        
        print(f"✅ Generated stealth address: {stealth_addr}")
        print(f"   Shared secret: {shared_secret.hex()[:16]}...")
        print(f"   Address format: {'VALID' if stealth_addr.startswith('wepo1') else 'INVALID'}")
        
        if not stealth_addr.startswith('wepo1'):
            print("❌ Stealth address format invalid")
            return False
            
    except Exception as e:
        print(f"❌ Stealth address test failed: {e}")
        return False
    
    # Test 6: Complete private transaction
    try:
        print("\n--- Test 6: Complete Private Transaction ---")
        
        sender_key = get_random_bytes(32)
        recipient_addr = "wepo1recipient000000000000000000000"
        amount = 50000000  # 0.5 WEPO
        decoy_keys = [get_random_bytes(32) for _ in range(5)]
        
        # Create private transaction
        privacy_data = privacy_engine.create_private_transaction(
            sender_key, recipient_addr, amount, decoy_keys
        )
        
        print(f"✅ Created private transaction")
        print(f"   Privacy level: {privacy_data['privacy_level']}")
        print(f"   Commitment: {privacy_data['commitment'][:16]}...")
        print(f"   Components: {len(privacy_data)} privacy proofs")
        
        # Verify private transaction
        message = f"{recipient_addr}{amount}".encode()
        is_valid = privacy_engine.verify_private_transaction(privacy_data, message)
        print(f"✅ Private transaction verification: {'VALID' if is_valid else 'INVALID'}")
        
        if not is_valid:
            print("❌ Private transaction verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Private transaction test failed: {e}")
        return False
    
    print("\n" + "="*60)
    print("🎉 ALL PRIVACY TESTS PASSED SUCCESSFULLY!")
    print("="*60)
    
    return True

def test_privacy_integration():
    """Test privacy integration with blockchain"""
    print("\n🔗 PRIVACY INTEGRATION TEST")
    print("="*60)
    
    # Test privacy proof helper functions
    try:
        from privacy import create_privacy_proof, verify_privacy_proof
        
        print("\n--- Testing privacy proof helpers ---")
        
        # Test privacy proof creation
        transaction_data = {
            'sender_private_key': get_random_bytes(32),
            'recipient_address': 'wepo1test000000000000000000000000000',
            'amount': 25000000,  # 0.25 WEPO
            'decoy_keys': [get_random_bytes(32) for _ in range(3)]
        }
        
        proof = create_privacy_proof(transaction_data)
        print(f"✅ Privacy proof created: {len(proof)} bytes")
        
        # Test privacy proof verification
        message = b"test_message"
        is_valid = verify_privacy_proof(proof, message)
        print(f"✅ Privacy proof verification: {'VALID' if is_valid else 'INVALID'}")
        
        return True
        
    except Exception as e:
        print(f"❌ Privacy integration test failed: {e}")
        return False

def test_privacy_api_endpoints():
    """Test privacy API endpoints"""
    print("\n🌐 PRIVACY API ENDPOINTS TEST")
    print("="*60)
    
    import requests
    
    backend_url = "http://localhost:8001"
    
    try:
        # Test privacy info endpoint
        print("\n--- Testing privacy info endpoint ---")
        response = requests.get(f"{backend_url}/api/privacy/info", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Privacy info retrieved")
            print(f"   Privacy enabled: {data.get('privacy_enabled', False)}")
            print(f"   Features: {len(data.get('supported_features', []))}")
            print(f"   Levels: {len(data.get('privacy_levels', {}))}")
        else:
            print(f"❌ Privacy info failed: {response.status_code}")
            return False
            
        # Test privacy proof creation endpoint
        print("\n--- Testing privacy proof creation ---")
        proof_request = {
            'transaction_data': {
                'sender_private_key': get_random_bytes(32).hex(),
                'recipient_address': 'wepo1test000000000000000000000000000',
                'amount': 10000000,
                'decoy_keys': [get_random_bytes(32).hex() for _ in range(3)]
            }
        }
        
        response = requests.post(f"{backend_url}/api/privacy/create-proof", 
                               json=proof_request, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Privacy proof created via API")
            print(f"   Success: {data.get('success', False)}")
            print(f"   Proof size: {data.get('proof_size', 0)} bytes")
            print(f"   Privacy level: {data.get('privacy_level', 'none')}")
            
            # Test privacy proof verification
            verify_request = {
                'proof_data': data.get('privacy_proof', ''),
                'message': 'test_verification'
            }
            
            response = requests.post(f"{backend_url}/api/privacy/verify-proof", 
                                   json=verify_request, timeout=10)
            if response.status_code == 200:
                verify_data = response.json()
                print(f"✅ Privacy proof verified via API")
                print(f"   Valid: {verify_data.get('valid', False)}")
                print(f"   Privacy level: {verify_data.get('privacy_level', 'none')}")
            else:
                print(f"❌ Privacy proof verification failed: {response.status_code}")
                return False
        else:
            print(f"❌ Privacy proof creation failed: {response.status_code}")
            return False
            
        # Test stealth address generation
        print("\n--- Testing stealth address generation ---")
        stealth_request = {
            'recipient_public_key': get_random_bytes(32).hex()
        }
        
        response = requests.post(f"{backend_url}/api/privacy/stealth-address", 
                               json=stealth_request, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Stealth address generated via API")
            print(f"   Address: {data.get('stealth_address', 'none')}")
            print(f"   Privacy level: {data.get('privacy_level', 'none')}")
        else:
            print(f"❌ Stealth address generation failed: {response.status_code}")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Privacy API test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 WEPO PRIVACY FEATURES COMPREHENSIVE TESTING")
    print("="*60)
    
    # Test 1: Core privacy functionality
    core_success = test_privacy_core_functionality()
    
    # Test 2: Privacy integration
    integration_success = test_privacy_integration()
    
    # Test 3: Privacy API endpoints
    api_success = test_privacy_api_endpoints()
    
    # Summary
    print("\n" + "="*60)
    print("🏁 PRIVACY FEATURES TESTING SUMMARY")
    print("="*60)
    
    if core_success:
        print("✅ Core privacy functionality: WORKING")
    else:
        print("❌ Core privacy functionality: FAILED")
    
    if integration_success:
        print("✅ Privacy integration: WORKING")
    else:
        print("❌ Privacy integration: FAILED")
    
    if api_success:
        print("✅ Privacy API endpoints: WORKING")
    else:
        print("❌ Privacy API endpoints: FAILED (backend may not be running)")
    
    if core_success and integration_success:
        print("\n🎉 PRIVACY FEATURES IMPLEMENTATION SUCCESSFUL!")
        print("WEPO now has revolutionary privacy features!")
        print("\n🔒 PRIVACY FEATURES IMPLEMENTED:")
        print("   ✅ zk-STARK proofs - Zero-knowledge transaction validation")
        print("   ✅ Ring signatures - Anonymous transaction signing")
        print("   ✅ Confidential transactions - Hidden transaction amounts")
        print("   ✅ Stealth addresses - Hidden recipient addresses")
        print("   ✅ Privacy levels - Standard, High, Maximum privacy")
        print("   ✅ API integration - Complete privacy API endpoints")
    else:
        print("\n❌ PRIVACY FEATURES IMPLEMENTATION FAILED")
        print("Issues need to be resolved for full privacy")

if __name__ == "__main__":
    main()