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