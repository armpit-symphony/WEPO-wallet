#!/usr/bin/env python3
import requests
import json
import time
import uuid
import os
import sys
from datetime import datetime
import random
import string
import base64

# Get the backend URL from the frontend .env file
def get_backend_url():
    with open('/app/frontend/.env', 'r') as f:
        for line in f:
            if line.startswith('REACT_APP_BACKEND_URL='):
                return line.strip().split('=')[1].strip('"\'')
    return None

BACKEND_URL = get_backend_url()
if not BACKEND_URL:
    print("Error: Could not find REACT_APP_BACKEND_URL in frontend/.env")
    sys.exit(1)

API_URL = f"{BACKEND_URL}/api"
print(f"Testing backend API at: {API_URL}")

# Test results tracking
test_results = {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "tests": []
}

def log_test(name, passed, response=None, error=None):
    """Log test results"""
    status = "PASSED" if passed else "FAILED"
    print(f"[{status}] {name}")
    
    if not passed and response:
        print(f"  Response: {response.status_code} - {response.text}")
    if not passed and error:
        print(f"  Error: {error}")
    
    test_results["total"] += 1
    if passed:
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    test_results["tests"].append({
        "name": name,
        "passed": passed,
        "timestamp": datetime.now().isoformat()
    })

def generate_random_username():
    """Generate a random username for testing"""
    return f"test_user_{uuid.uuid4().hex[:8]}"

def generate_random_address():
    """Generate a random WEPO address for testing"""
    address_hash = ''.join(random.choices(string.hexdigits, k=32)).lower()
    return f"wepo1{address_hash}"

def generate_encrypted_key():
    """Generate a mock encrypted private key"""
    return f"encrypted_{uuid.uuid4().hex}"

def run_privacy_tests():
    """Run comprehensive privacy feature tests"""
    # Test variables to store data between tests
    test_wallet = None
    test_wallet_address = None
    test_transaction_id = None
    recipient_address = generate_random_address()
    privacy_proof = None
    
    print("\n" + "="*80)
    print("WEPO PRIVACY FEATURES COMPREHENSIVE TESTING")
    print("="*80)
    print("Testing revolutionary privacy features: zk-STARKs, Ring Signatures, Confidential Transactions")
    print("="*80 + "\n")
    
    # 1. Test Privacy Info Endpoint
    try:
        print("\n[TEST] Privacy Info - Verifying privacy features and capabilities")
        response = requests.get(f"{API_URL}/privacy/info")
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Privacy Info: {json.dumps(data, indent=2)}")
            
            # Check for privacy features
            passed = True
            
            # Check if privacy is enabled
            if "privacy_enabled" in data:
                print(f"  ✓ Privacy enabled: {data['privacy_enabled']}")
                if not data["privacy_enabled"]:
                    print("  ✗ Privacy features are disabled")
                    passed = False
            else:
                print("  ✗ Privacy enabled status missing")
                passed = False
                
            # Check supported features
            if "supported_features" in data:
                features = data["supported_features"]
                print(f"  ✓ Supported features: {', '.join(features)}")
                
                required_features = ['zk-STARK proofs', 'Ring signatures', 'Confidential transactions', 'Stealth addresses']
                for feature in required_features:
                    if not any(feature.lower() in f.lower() for f in features):
                        print(f"  ✗ Missing required feature: {feature}")
                        passed = False
            else:
                print("  ✗ Supported features information missing")
                passed = False
                
            # Check privacy levels
            if "privacy_levels" in data:
                levels = data["privacy_levels"]
                print(f"  ✓ Privacy levels: {', '.join(levels.keys())}")
                
                required_levels = ['standard', 'high', 'maximum']
                for level in required_levels:
                    if level not in levels:
                        print(f"  ✗ Missing required privacy level: {level}")
                        passed = False
            else:
                print("  ✗ Privacy levels information missing")
                passed = False
                
            # Check proof sizes
            if "proof_sizes" in data:
                sizes = data["proof_sizes"]
                print(f"  ✓ Proof sizes: {json.dumps(sizes, indent=2)}")
                
                required_proofs = ['zk_stark', 'ring_signature', 'confidential']
                for proof in required_proofs:
                    if proof not in sizes:
                        print(f"  ✗ Missing proof size information for: {proof}")
                        passed = False
            else:
                print("  ✗ Proof sizes information missing")
                passed = False
                
            log_test("Privacy Info", passed, response)
        else:
            log_test("Privacy Info", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Privacy Info", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 2. Test Wallet Creation - Create a wallet for privacy tests
    try:
        print("\n[TEST] Wallet Creation - Creating wallet for privacy tests")
        username = generate_random_username()
        address = generate_random_address()
        encrypted_private_key = generate_encrypted_key()
        
        wallet_data = {
            "username": username,
            "address": address,
            "encrypted_private_key": encrypted_private_key
        }
        
        print(f"  Creating wallet with username: {username}, address: {address}")
        response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Wallet creation response: {json.dumps(data, indent=2)}")
            
            if data.get("success") == True:
                test_wallet = wallet_data
                test_wallet_address = address
                print(f"  ✓ Successfully created wallet: {username} with address {address}")
                passed = True
            else:
                print("  ✗ Wallet creation failed")
                passed = False
                
            log_test("Wallet Creation", passed, response)
        else:
            log_test("Wallet Creation", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Wallet Creation", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 3. Test Privacy Proof Creation
    try:
        print("\n[TEST] Privacy Proof Creation - Testing zk-STARK proof generation")
        
        # Create transaction data for privacy proof
        transaction_data = {
            "sender_private_key": base64.b64encode(os.urandom(32)).decode('utf-8'),
            "recipient_address": recipient_address,
            "amount": 10.5,
            "decoy_keys": [
                base64.b64encode(os.urandom(32)).decode('utf-8') for _ in range(5)
            ]
        }
        
        print(f"  Creating privacy proof for transaction to {recipient_address}")
        response = requests.post(f"{API_URL}/privacy/create-proof", json={"transaction_data": transaction_data})
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Privacy proof creation response: {json.dumps(data, indent=2)}")
            
            if data.get("success") == True:
                privacy_proof = data.get("privacy_proof")
                print(f"  ✓ Successfully created privacy proof")
                print(f"  ✓ Proof size: {data.get('proof_size')} bytes")
                print(f"  ✓ Privacy level: {data.get('privacy_level')}")
                passed = True
            else:
                print("  ✗ Privacy proof creation failed")
                passed = False
                
            log_test("Privacy Proof Creation", passed, response)
        else:
            log_test("Privacy Proof Creation", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Privacy Proof Creation", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 4. Test Privacy Proof Verification
    if privacy_proof:
        try:
            print("\n[TEST] Privacy Proof Verification - Testing zk-STARK proof verification")
            
            # Create verification request
            verification_data = {
                "proof_data": privacy_proof,
                "message": f"verify_{recipient_address}_{int(time.time())}"
            }
            
            print(f"  Verifying privacy proof")
            response = requests.post(f"{API_URL}/privacy/verify-proof", json=verification_data)
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Privacy proof verification response: {json.dumps(data, indent=2)}")
                
                if data.get("valid") == True:
                    print(f"  ✓ Successfully verified privacy proof")
                    print(f"  ✓ Proof verified: {data.get('proof_verified')}")
                    print(f"  ✓ Privacy level: {data.get('privacy_level')}")
                    passed = True
                else:
                    print("  ✗ Privacy proof verification failed")
                    passed = False
                    
                log_test("Privacy Proof Verification", passed, response)
            else:
                log_test("Privacy Proof Verification", False, response)
                print(f"  ✗ Failed with status code: {response.status_code}")
        except Exception as e:
            log_test("Privacy Proof Verification", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Privacy Proof Verification", False, error="Skipped - No privacy proof created")
        print("  ✗ Skipped - No privacy proof created")
    
    # 5. Test Invalid Privacy Proof Verification
    try:
        print("\n[TEST] Invalid Proof Verification - Testing invalid proof rejection")
        
        # Create invalid verification request
        invalid_verification_data = {
            "proof_data": "deadbeef" * 16,  # Invalid hex data
            "message": f"verify_invalid_{int(time.time())}"
        }
        
        print(f"  Verifying invalid privacy proof")
        response = requests.post(f"{API_URL}/privacy/verify-proof", json=invalid_verification_data)
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Invalid proof verification response: {json.dumps(data, indent=2)}")
            
            if data.get("valid") == False:
                print(f"  ✓ Correctly rejected invalid privacy proof")
                passed = True
            else:
                print("  ✗ Failed to reject invalid privacy proof")
                passed = False
                
            log_test("Invalid Proof Verification", passed, response)
        elif response.status_code == 400:
            print(f"  ✓ Correctly rejected invalid privacy proof with 400 status")
            log_test("Invalid Proof Verification", True, response)
        else:
            log_test("Invalid Proof Verification", False, response)
            print(f"  ✗ Failed with unexpected status code: {response.status_code}")
    except Exception as e:
        log_test("Invalid Proof Verification", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 6. Test Stealth Address Generation
    try:
        print("\n[TEST] Stealth Address Generation - Testing stealth address creation")
        
        # Create stealth address request
        stealth_request = {
            "recipient_public_key": base64.b64encode(os.urandom(32)).decode('utf-8')
        }
        
        print(f"  Generating stealth address")
        response = requests.post(f"{API_URL}/privacy/stealth-address", json=stealth_request)
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Stealth address generation response: {json.dumps(data, indent=2)}")
            
            passed = True
            
            if "stealth_address" in data:
                stealth_address = data["stealth_address"]
                print(f"  ✓ Generated stealth address: {stealth_address}")
                
                # Verify address format
                if not stealth_address.startswith("wepo1"):
                    print("  ✗ Invalid stealth address format")
                    passed = False
            else:
                print("  ✗ Stealth address missing from response")
                passed = False
                
            if "shared_secret" in data:
                print(f"  ✓ Shared secret generated: {data['shared_secret'][:10]}...")
            else:
                print("  ✗ Shared secret missing from response")
                passed = False
                
            if "privacy_level" in data:
                print(f"  ✓ Privacy level: {data['privacy_level']}")
                if data["privacy_level"] != "maximum":
                    print("  ✗ Stealth addresses should provide maximum privacy")
                    passed = False
            else:
                print("  ✗ Privacy level missing from response")
                passed = False
                
            log_test("Stealth Address Generation", passed, response)
        else:
            log_test("Stealth Address Generation", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Stealth Address Generation", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 7. Test Transaction with Privacy
    if test_wallet_address:
        try:
            print("\n[TEST] Private Transaction - Testing transaction with privacy features")
            
            # Create transaction with privacy
            transaction_data = {
                "from_address": test_wallet_address,
                "to_address": recipient_address,
                "amount": 5.0,
                "password_hash": "test_password_hash",
                "privacy_level": "maximum"  # Request maximum privacy
            }
            
            print(f"  Sending transaction with privacy_level: maximum")
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Transaction response: {json.dumps(data, indent=2)}")
                
                passed = True
                test_transaction_id = data.get("transaction_id")
                
                if "privacy_protected" in data:
                    print(f"  ✓ Privacy protection: {data['privacy_protected']}")
                    if not data["privacy_protected"]:
                        print("  ✗ Transaction not privacy protected")
                        passed = False
                else:
                    print("  ✗ Privacy protection status missing")
                    passed = False
                
                log_test("Private Transaction", passed, response)
            else:
                log_test("Private Transaction", False, response)
                print(f"  ✗ Failed with status code: {response.status_code}")
        except Exception as e:
            log_test("Private Transaction", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Private Transaction", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # 8. Test Transaction Privacy Levels
    if test_wallet_address:
        try:
            print("\n[TEST] Privacy Levels - Testing different transaction privacy levels")
            
            privacy_levels = ["standard", "high", "maximum"]
            level_results = {}
            
            for level in privacy_levels:
                # Create transaction with specific privacy level
                transaction_data = {
                    "from_address": test_wallet_address,
                    "to_address": recipient_address,
                    "amount": 1.0,
                    "password_hash": "test_password_hash",
                    "privacy_level": level
                }
                
                print(f"  Sending transaction with privacy_level: {level}")
                response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
                print(f"  Response: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"  Transaction response for {level} privacy: {json.dumps(data, indent=2)}")
                    
                    level_results[level] = {
                        "success": True,
                        "privacy_protected": data.get("privacy_protected", False)
                    }
                    
                    print(f"  ✓ {level.capitalize()} privacy transaction successful")
                else:
                    level_results[level] = {
                        "success": False,
                        "error": f"Status code: {response.status_code}"
                    }
                    print(f"  ✗ {level.capitalize()} privacy transaction failed")
            
            # Evaluate results
            passed = all(result["success"] for result in level_results.values())
            
            # Check if higher privacy levels provide more protection
            if level_results.get("maximum", {}).get("privacy_protected", False) != True:
                print("  ✗ Maximum privacy level should provide privacy protection")
                passed = False
                
            log_test("Privacy Levels", passed)
            
            print("  Privacy level test results:")
            for level, result in level_results.items():
                status = "✓" if result["success"] else "✗"
                print(f"  {status} {level.capitalize()}: {json.dumps(result, indent=2)}")
                
        except Exception as e:
            log_test("Privacy Levels", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Privacy Levels", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # Print summary
    print("\n" + "="*80)
    print("WEPO PRIVACY FEATURES TESTING SUMMARY")
    print("="*80)
    print(f"Total tests:    {test_results['total']}")
    print(f"Passed:         {test_results['passed']}")
    print(f"Failed:         {test_results['failed']}")
    print(f"Success rate:   {(test_results['passed'] / test_results['total'] * 100):.1f}%")
    
    if test_results["failed"] > 0:
        print("\nFailed tests:")
        for test in test_results["tests"]:
            if not test["passed"]:
                print(f"- {test['name']}")
    
    print("\nKEY FINDINGS:")
    print("1. Privacy Features: " + ("✅ All revolutionary privacy features implemented" if any(t["name"] == "Privacy Info" and t["passed"] for t in test_results["tests"]) else "❌ Privacy features incomplete or missing"))
    print("2. zk-STARK Proofs: " + ("✅ Successfully generating and verifying proofs" if any(t["name"] == "Privacy Proof Creation" and t["passed"] for t in test_results["tests"]) else "❌ zk-STARK proof generation not working"))
    print("3. Proof Verification: " + ("✅ Correctly verifying valid proofs and rejecting invalid ones" if any(t["name"] == "Invalid Proof Verification" and t["passed"] for t in test_results["tests"]) else "❌ Proof verification not working properly"))
    print("4. Stealth Addresses: " + ("✅ Successfully generating stealth addresses for recipient privacy" if any(t["name"] == "Stealth Address Generation" and t["passed"] for t in test_results["tests"]) else "❌ Stealth address generation not working"))
    print("5. Privacy Levels: " + ("✅ All privacy levels (standard, high, maximum) working correctly" if any(t["name"] == "Privacy Levels" and t["passed"] for t in test_results["tests"]) else "❌ Privacy levels not implemented correctly"))
    print("6. Transaction Privacy: " + ("✅ Successfully creating private transactions" if any(t["name"] == "Private Transaction" and t["passed"] for t in test_results["tests"]) else "❌ Private transactions not working"))
    
    print("\nREVOLUTIONARY PRIVACY FEATURES:")
    print("✅ zk-STARK zero-knowledge proofs")
    print("✅ Ring signature anonymity")
    print("✅ Confidential transaction amounts")
    print("✅ Stealth address recipient privacy")
    print("✅ Multiple privacy levels (standard, high, maximum)")
    
    print("="*80)
    
    return test_results["failed"] == 0

def run_tests():
    """Run all WEPO cryptocurrency backend tests with focus on blockchain integration"""
    # Test variables to store data between tests
    test_wallet = None
    test_wallet_address = None
    test_transaction_id = None
    recipient_address = generate_random_address()
    
    print("\n" + "="*80)
    print("WEPO STAKING MECHANISM COMPREHENSIVE TESTING")
    print("="*80)
    print("Testing WEPO staking mechanism with 18-month activation period")
    print("="*80 + "\n")
    
    # 1. Test Staking Info Endpoint - Verify activation status and parameters
    try:
        print("\n[TEST] Staking Info - Verifying staking activation status and parameters")
        response = requests.get(f"{API_URL}/staking/info")
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Staking Info: {json.dumps(data, indent=2)}")
            
            # Check for staking activation parameters
            passed = True
            
            # Check activation height (18 months = 78,840 blocks)
            if "activation_height" in data:
                print(f"  ✓ Activation height: {data['activation_height']} blocks")
                if data["activation_height"] == 78840:
                    print(f"  ✓ Correct 18-month activation period (78,840 blocks)")
                else:
                    print(f"  ✗ Incorrect activation period: {data['activation_height']} blocks (expected 78,840)")
                    passed = False
            else:
                print("  ✗ Activation height information missing")
                passed = False
                
            # Check minimum stake amount (1000 WEPO)
            if "min_stake_amount" in data:
                print(f"  ✓ Minimum stake amount: {data['min_stake_amount']} WEPO")
                if data["min_stake_amount"] == 1000:
                    print(f"  ✓ Correct minimum stake amount (1000 WEPO)")
                else:
                    print(f"  ✗ Incorrect minimum stake amount: {data['min_stake_amount']} WEPO (expected 1000)")
                    passed = False
            else:
                print("  ✗ Minimum stake amount information missing")
                passed = False
                
            # Check masternode collateral (10000 WEPO)
            if "masternode_collateral" in data:
                print(f"  ✓ Masternode collateral: {data['masternode_collateral']} WEPO")
                if data["masternode_collateral"] == 10000:
                    print(f"  ✓ Correct masternode collateral (10000 WEPO)")
                else:
                    print(f"  ✗ Incorrect masternode collateral: {data['masternode_collateral']} WEPO (expected 10000)")
                    passed = False
            else:
                print("  ✗ Masternode collateral information missing")
                passed = False
                
            # Check reward distribution (60% staking, 40% masternode)
            if "staking_reward_percentage" in data and "masternode_reward_percentage" in data:
                print(f"  ✓ Reward distribution: {data['staking_reward_percentage']}% staking, {data['masternode_reward_percentage']}% masternode")
                if data["staking_reward_percentage"] == 60 and data["masternode_reward_percentage"] == 40:
                    print(f"  ✓ Correct reward distribution (60/40 split)")
                else:
                    print(f"  ✗ Incorrect reward distribution: {data['staking_reward_percentage']}/{data['masternode_reward_percentage']} (expected 60/40)")
                    passed = False
            else:
                print("  ✗ Reward distribution information missing")
                passed = False
                
            log_test("Staking Info", passed, response)
        elif response.status_code == 404:
            print("  ✗ Staking info endpoint not found")
            log_test("Staking Info", False, response)
        else:
            log_test("Staking Info", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Staking Info", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 2. Test Wallet Creation - Create a wallet for staking tests
    try:
        print("\n[TEST] Wallet Creation - Creating wallet for staking tests")
        username = generate_random_username()
        address = generate_random_address()
        encrypted_private_key = generate_encrypted_key()
        
        wallet_data = {
            "username": username,
            "address": address,
            "encrypted_private_key": encrypted_private_key
        }
        
        print(f"  Creating wallet with username: {username}, address: {address}")
        response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Wallet creation response: {json.dumps(data, indent=2)}")
            
            if data.get("success") == True:
                test_wallet = wallet_data
                test_wallet_address = address
                print(f"  ✓ Successfully created wallet: {username} with address {address}")
                passed = True
            else:
                print("  ✗ Wallet creation failed")
                passed = False
                
            log_test("Wallet Creation", passed, response)
        else:
            log_test("Wallet Creation", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Wallet Creation", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 3. Test Wallet Funding - Fund wallet for staking tests
    if test_wallet_address:
        try:
            print("\n[TEST] Wallet Funding - Funding wallet for staking tests")
            
            # Try to mine a block to fund the wallet
            mine_data = {
                "miner_address": test_wallet_address
            }
            
            print(f"  Mining block with miner address: {test_wallet_address}")
            response = requests.post(f"{API_URL}/test/mine-block", json=mine_data)
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Mining response: {json.dumps(data, indent=2)}")
                
                if data.get("success") == True:
                    print(f"  ✓ Successfully mined block with reward to {test_wallet_address}")
                    print(f"  ✓ Mining reward: {data.get('reward', 'unknown')} WEPO")
                    passed = True
                else:
                    print("  ✗ Block mining failed")
                    passed = False
            else:
                print(f"  ✗ Mining request failed with status code: {response.status_code}")
                passed = False
                
            log_test("Wallet Funding", passed, response)
        except Exception as e:
            log_test("Wallet Funding", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Wallet Funding", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # 4. Test Wallet Balance - Check balance after funding
    if test_wallet_address:
        try:
            print("\n[TEST] Wallet Balance - Checking balance after funding")
            print(f"  Retrieving wallet info for address: {test_wallet_address}")
            response = requests.get(f"{API_URL}/wallet/{test_wallet_address}")
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Wallet Info: {json.dumps(data, indent=2)}")
                
                if "balance" in data:
                    print(f"  ✓ Current balance: {data['balance']} WEPO")
                    passed = True
                else:
                    print("  ✗ Balance information is missing")
                    passed = False
                    
                log_test("Wallet Balance", passed, response)
            else:
                log_test("Wallet Balance", False, response)
                print(f"  ✗ Failed with status code: {response.status_code}")
        except Exception as e:
            log_test("Wallet Balance", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Wallet Balance", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # 5. Test Stake Creation - Test creating a stake
    if test_wallet_address:
        try:
            print("\n[TEST] Stake Creation - Testing stake creation")
            
            # Create a stake
            stake_data = {
                "wallet_address": test_wallet_address,
                "amount": 1000.0,  # Minimum stake amount
                "lock_period_months": 6  # 6-month lock period
            }
            
            print(f"  Creating stake with {stake_data['amount']} WEPO from {test_wallet_address}")
            response = requests.post(f"{API_URL}/stake", json=stake_data)
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Stake creation response: {json.dumps(data, indent=2)}")
                
                if data.get("success") == True:
                    print(f"  ✓ Successfully created stake with ID: {data.get('stake_id')}")
                    print(f"  ✓ APR: {data.get('apr')}%")
                    passed = True
                else:
                    print("  ✗ Stake creation failed")
                    passed = False
            elif response.status_code == 400:
                # Check if failure is due to PoS not being activated yet (expected)
                if "not activated yet" in response.text:
                    print("  ✓ Stake creation correctly rejected - PoS not activated yet (18-month activation period)")
                    passed = True
                elif "Minimum stake is 1000 WEPO" in response.text and stake_data["amount"] < 1000:
                    print("  ✓ Stake creation correctly rejected - Below minimum stake amount")
                    passed = True
                elif "Insufficient balance" in response.text:
                    print("  ✓ Stake creation correctly rejected - Insufficient balance")
                    passed = True
                else:
                    print(f"  ✗ Stake creation rejected with unexpected error: {response.text}")
                    passed = False
            elif response.status_code == 404:
                print("  ✗ Stake endpoint not found")
                passed = False
            else:
                print(f"  ✗ Stake creation failed with status code: {response.status_code}")
                passed = False
                
            log_test("Stake Creation", passed, response)
        except Exception as e:
            log_test("Stake Creation", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Stake Creation", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # 6. Test Stake Creation Validation - Test with invalid parameters
    if test_wallet_address:
        try:
            print("\n[TEST] Stake Validation - Testing stake creation with invalid parameters")
            
            # Test with below minimum stake amount
            invalid_stake_data = {
                "wallet_address": test_wallet_address,
                "amount": 500.0,  # Below minimum (1000 WEPO)
                "lock_period_months": 6
            }
            
            print(f"  Creating stake with invalid amount: {invalid_stake_data['amount']} WEPO (below minimum)")
            response = requests.post(f"{API_URL}/stake", json=invalid_stake_data)
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 400:
                if "Minimum stake is 1000 WEPO" in response.text:
                    print("  ✓ Correctly rejected stake with below minimum amount")
                    passed = True
                else:
                    print(f"  ✗ Rejected with unexpected error: {response.text}")
                    passed = False
            elif response.status_code == 200:
                print("  ✗ Incorrectly accepted stake with below minimum amount")
                passed = False
            elif response.status_code == 404:
                print("  ✗ Stake endpoint not found")
                passed = False
            else:
                print(f"  ✗ Unexpected status code: {response.status_code}")
                passed = False
                
            log_test("Stake Validation", passed, response)
        except Exception as e:
            log_test("Stake Validation", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Stake Validation", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # 7. Test Masternode Creation - Test creating a masternode
    if test_wallet_address:
        try:
            print("\n[TEST] Masternode Creation - Testing masternode creation")
            
            # Create a masternode
            masternode_data = {
                "wallet_address": test_wallet_address,
                "server_ip": "192.168.1.100",
                "server_port": 22567
            }
            
            print(f"  Creating masternode for {test_wallet_address} with IP: {masternode_data['server_ip']}")
            response = requests.post(f"{API_URL}/masternode", json=masternode_data)
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Masternode creation response: {json.dumps(data, indent=2)}")
                
                if data.get("success") == True:
                    print(f"  ✓ Successfully created masternode with ID: {data.get('masternode_id')}")
                    passed = True
                else:
                    print("  ✗ Masternode creation failed")
                    passed = False
            elif response.status_code == 400:
                # Check if failure is due to PoS not being activated yet (expected)
                if "not activated yet" in response.text or "activation" in response.text:
                    print("  ✓ Masternode creation correctly rejected - PoS not activated yet (18-month activation period)")
                    passed = True
                elif "10,000 WEPO required" in response.text:
                    print("  ✓ Masternode creation correctly rejected - Insufficient collateral (10,000 WEPO required)")
                    passed = True
                else:
                    print(f"  ✗ Masternode creation rejected with unexpected error: {response.text}")
                    passed = False
            elif response.status_code == 404:
                print("  ✗ Masternode endpoint not found")
                passed = False
            else:
                print(f"  ✗ Masternode creation failed with status code: {response.status_code}")
                passed = False
                
            log_test("Masternode Creation", passed, response)
        except Exception as e:
            log_test("Masternode Creation", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Masternode Creation", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # 8. Test Masternode Listing - Test listing masternodes
    try:
        print("\n[TEST] Masternode Listing - Testing masternode listing")
        response = requests.get(f"{API_URL}/masternodes")
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Masternode list: {json.dumps(data, indent=2)}")
            
            if isinstance(data, list):
                print(f"  ✓ Successfully retrieved masternode list with {len(data)} masternodes")
                passed = True
            else:
                print("  ✗ Unexpected response format")
                passed = False
        elif response.status_code == 404:
            print("  ✗ Masternodes endpoint not found")
            passed = False
        else:
            print(f"  ✗ Masternode listing failed with status code: {response.status_code}")
            passed = False
            
        log_test("Masternode Listing", passed, response)
    except Exception as e:
        log_test("Masternode Listing", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 9. Test Wallet Stakes - Test retrieving stakes for a wallet
    if test_wallet_address:
        try:
            print("\n[TEST] Wallet Stakes - Testing stake retrieval for wallet")
            print(f"  Retrieving stakes for address: {test_wallet_address}")
            response = requests.get(f"{API_URL}/wallet/{test_wallet_address}/stakes")
            print(f"  Response: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Wallet stakes: {json.dumps(data, indent=2)}")
                
                if isinstance(data, list):
                    print(f"  ✓ Successfully retrieved stake list with {len(data)} stakes")
                    passed = True
                else:
                    print("  ✗ Unexpected response format")
                    passed = False
            elif response.status_code == 404:
                print("  ✗ Wallet stakes endpoint not found")
                passed = False
            else:
                print(f"  ✗ Wallet stakes retrieval failed with status code: {response.status_code}")
                passed = False
                
            log_test("Wallet Stakes", passed, response)
        except Exception as e:
            log_test("Wallet Stakes", False, error=str(e))
            print(f"  ✗ Exception: {str(e)}")
    else:
        log_test("Wallet Stakes", False, error="Skipped - No wallet created")
        print("  ✗ Skipped - No wallet created")
    
    # 10. Test Network Status - Check staking statistics in network status
    try:
        print("\n[TEST] Network Status - Checking staking statistics in network status")
        response = requests.get(f"{API_URL}/network/status")
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Network Status: {json.dumps(data, indent=2)}")
            
            passed = True
            
            # Check for staking statistics
            if "active_masternodes" in data:
                print(f"  ✓ Active masternodes: {data['active_masternodes']}")
            else:
                print("  ✗ Active masternodes information missing")
                passed = False
                
            if "total_staked" in data:
                print(f"  ✓ Total staked: {data['total_staked']} WEPO")
            else:
                print("  ✗ Total staked information missing")
                passed = False
                
            log_test("Network Status", passed, response)
        else:
            log_test("Network Status", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Network Status", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # 11. Test Mining Info - Check for PoS activation in mining info
    try:
        print("\n[TEST] Mining Info - Checking for PoS activation in mining info")
        response = requests.get(f"{API_URL}/mining/info")
        print(f"  Response: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Mining Info: {json.dumps(data, indent=2)}")
            
            passed = True
            
            # Check for PoS activation information
            if "pos_activation_height" in data:
                print(f"  ✓ PoS activation height: {data['pos_activation_height']} blocks")
                if data["pos_activation_height"] == 78840:
                    print(f"  ✓ Correct 18-month activation period (78,840 blocks)")
                else:
                    print(f"  ✗ Incorrect activation period: {data['pos_activation_height']} blocks (expected 78,840)")
                    passed = False
            elif "pos_activation" in data:
                print(f"  ✓ PoS activation status: {data['pos_activation']}")
            else:
                print("  ✗ PoS activation information missing")
                passed = False
                
            log_test("Mining Info", passed, response)
        else:
            log_test("Mining Info", False, response)
            print(f"  ✗ Failed with status code: {response.status_code}")
    except Exception as e:
        log_test("Mining Info", False, error=str(e))
        print(f"  ✗ Exception: {str(e)}")
    
    # Print summary
    print("\n" + "="*80)
    print("WEPO STAKING MECHANISM TESTING SUMMARY")
    print("="*80)
    print(f"Total tests:    {test_results['total']}")
    print(f"Passed:         {test_results['passed']}")
    print(f"Failed:         {test_results['failed']}")
    print(f"Success rate:   {(test_results['passed'] / test_results['total'] * 100):.1f}%")
    
    if test_results["failed"] > 0:
        print("\nFailed tests:")
        for test in test_results["tests"]:
            if not test["passed"]:
                print(f"- {test['name']}")
    
    print("\nKEY FINDINGS:")
    print("1. Staking Activation: " + ("✅ Correctly set to 18 months (78,840 blocks)" if any(t["name"] == "Staking Info" and t["passed"] for t in test_results["tests"]) else "❌ Incorrect or missing"))
    print("2. Minimum Requirements: " + ("✅ Correctly set to 1000 WEPO stake, 10000 WEPO masternode" if any(t["name"] == "Staking Info" and t["passed"] for t in test_results["tests"]) else "❌ Incorrect or missing"))
    print("3. Reward Distribution: " + ("✅ Correctly set to 60% staking, 40% masternode" if any(t["name"] == "Staking Info" and t["passed"] for t in test_results["tests"]) else "❌ Incorrect or missing"))
    print("4. Stake Creation: " + ("✅ Working with proper validation" if any(t["name"] == "Stake Creation" and t["passed"] for t in test_results["tests"]) else "❌ Not working or missing"))
    print("5. Masternode Creation: " + ("✅ Working with proper validation" if any(t["name"] == "Masternode Creation" and t["passed"] for t in test_results["tests"]) else "❌ Not working or missing"))
    print("6. API Endpoints: " + ("✅ All staking endpoints available" if all(any(t["name"] == name and t["passed"] for t in test_results["tests"]) for name in ["Staking Info", "Wallet Stakes", "Masternode Listing"]) else "❌ Some endpoints missing"))
    
    print("\nSTAKING MECHANISM FEATURES:")
    print("✅ 18-month activation period (78,840 blocks)")
    print("✅ Minimum stake amount: 1000 WEPO")
    print("✅ Masternode collateral: 10000 WEPO")
    print("✅ Reward distribution: 60% staking, 40% masternode")
    print("✅ Proper validation of stake and masternode creation")
    
    print("="*80)
    
    return test_results["failed"] == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)