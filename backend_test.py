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
    """Run all WEPO cryptocurrency backend tests"""
    # Test variables to store data between tests
    test_wallet = None
    test_wallet_address = None
    test_transaction_id = None
    test_stake_id = None
    test_masternode_id = None
    test_swap_id = None
    
    # 1. Test Network Status API
    try:
        response = requests.get(f"{API_URL}/network/status")
        print(f"  Network Status response: {response.status_code} - {response.text}")
        passed = response.status_code == 200 and "block_height" in response.json()
        log_test("Network Status API", passed, response)
        if passed:
            print(f"  Network Status: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        log_test("Network Status API", False, error=str(e))
    
    # 2. Test Wallet Creation
    try:
        username = generate_random_username()
        address = generate_random_address()
        encrypted_private_key = generate_encrypted_key()
        
        wallet_data = {
            "username": username,
            "address": address,
            "encrypted_private_key": encrypted_private_key
        }
        
        response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
        passed = response.status_code == 200 and response.json().get("success") == True
        log_test("Wallet Creation", passed, response)
        
        if passed:
            test_wallet = wallet_data
            test_wallet_address = address
            print(f"  Created wallet: {username} with address {address}")
    except Exception as e:
        log_test("Wallet Creation", False, error=str(e))
    
    # 3. Test Wallet Info
    if test_wallet_address:
        try:
            response = requests.get(f"{API_URL}/wallet/{test_wallet_address}")
            passed = response.status_code == 200 and "balance" in response.json()
            log_test("Wallet Info", passed, response)
            if passed:
                print(f"  Wallet Info: {json.dumps(response.json(), indent=2)}")
        except Exception as e:
            log_test("Wallet Info", False, error=str(e))
    else:
        log_test("Wallet Info", False, error="Skipped - No wallet created")
    
    # 4. Test Transaction History
    if test_wallet_address:
        try:
            response = requests.get(f"{API_URL}/wallet/{test_wallet_address}/transactions")
            passed = response.status_code == 200
            log_test("Transaction History", passed, response)
            if passed:
                print(f"  Transaction count: {len(response.json())}")
        except Exception as e:
            log_test("Transaction History", False, error=str(e))
    else:
        log_test("Transaction History", False, error="Skipped - No wallet created")
    
    # 5. Test Send Transaction (should fail due to insufficient balance)
    if test_wallet_address:
        try:
            transaction_data = {
                "from_address": test_wallet_address,
                "to_address": generate_random_address(),
                "amount": 100.0,
                "password_hash": "test_password_hash"
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            # This should fail with 400 due to insufficient balance
            passed = response.status_code == 400 and "Insufficient balance" in response.text
            log_test("Send Transaction (Insufficient Balance)", passed, response)
            
            if passed:
                print("  Transaction correctly failed due to insufficient balance")
        except Exception as e:
            log_test("Send Transaction (Insufficient Balance)", False, error=str(e))
    else:
        log_test("Send Transaction (Insufficient Balance)", False, error="Skipped - No wallet created")
    
    # 6. Test Staking (should fail due to minimum requirement)
    if test_wallet_address:
        try:
            stake_data = {
                "wallet_address": test_wallet_address,
                "amount": 100.0,  # Below minimum 1000 WEPO
                "lock_period_months": 12
            }
            
            response = requests.post(f"{API_URL}/stake", json=stake_data)
            # This should fail with 400 due to minimum stake requirement
            print(f"  Staking response: {response.status_code} - {response.text}")
            passed = response.status_code == 400 and "Minimum stake is 1000 WEPO" in response.text
            log_test("Staking (Minimum Requirement)", passed, response)
            
            if passed:
                print("  Staking correctly failed due to minimum requirement")
        except Exception as e:
            log_test("Staking (Minimum Requirement)", False, error=str(e))
    else:
        log_test("Staking (Minimum Requirement)", False, error="Skipped - No wallet created")
    
    # 7. Test Masternode Setup (should fail due to collateral requirement)
    if test_wallet_address:
        try:
            masternode_data = {
                "wallet_address": test_wallet_address,
                "server_ip": f"192.168.1.{random.randint(2, 254)}",
                "server_port": 22567
            }
            
            response = requests.post(f"{API_URL}/masternode", json=masternode_data)
            # This should fail with 400 due to collateral requirement
            passed = response.status_code == 400 and "10,000 WEPO required" in response.text
            log_test("Masternode Setup (Collateral Requirement)", passed, response)
            
            if passed:
                print("  Masternode setup correctly failed due to collateral requirement")
        except Exception as e:
            log_test("Masternode Setup (Collateral Requirement)", False, error=str(e))
    else:
        log_test("Masternode Setup (Collateral Requirement)", False, error="Skipped - No wallet created")
    
    # 8. Test BTC-WEPO DEX Swap (should fail for sell due to insufficient balance)
    if test_wallet_address:
        try:
            swap_data = {
                "wepo_address": test_wallet_address,
                "btc_address": "bc1" + ''.join(random.choices(string.hexdigits, k=32)).lower(),
                "btc_amount": 1.0,
                "swap_type": "sell"
            }
            
            response = requests.post(f"{API_URL}/dex/swap", json=swap_data)
            # This should fail with 400 due to insufficient WEPO balance
            passed = response.status_code == 400 and "Insufficient WEPO balance" in response.text
            log_test("BTC-WEPO DEX Swap (Sell - Insufficient Balance)", passed, response)
            
            if passed:
                print("  DEX swap (sell) correctly failed due to insufficient balance")
        except Exception as e:
            log_test("BTC-WEPO DEX Swap (Sell - Insufficient Balance)", False, error=str(e))
    else:
        log_test("BTC-WEPO DEX Swap (Sell - Insufficient Balance)", False, error="Skipped - No wallet created")
    
    # 9. Test BTC-WEPO DEX Swap (buy should succeed)
    if test_wallet_address:
        try:
            swap_data = {
                "wepo_address": test_wallet_address,
                "btc_address": "bc1" + ''.join(random.choices(string.hexdigits, k=32)).lower(),
                "btc_amount": 1.0,
                "swap_type": "buy"
            }
            
            response = requests.post(f"{API_URL}/dex/swap", json=swap_data)
            passed = response.status_code == 200 and "swap_id" in response.json()
            log_test("BTC-WEPO DEX Swap (Buy)", passed, response)
            
            if passed:
                test_swap_id = response.json().get("swap_id")
                print(f"  Created DEX swap: {test_swap_id}")
                print(f"  Swap details: {json.dumps(response.json(), indent=2)}")
        except Exception as e:
            log_test("BTC-WEPO DEX Swap (Buy)", False, error=str(e))
    else:
        log_test("BTC-WEPO DEX Swap (Buy)", False, error="Skipped - No wallet created")
    
    # 10. Test DEX Exchange Rate
    try:
        response = requests.get(f"{API_URL}/dex/rate")
        passed = response.status_code == 200 and "btc_to_wepo" in response.json()
        log_test("DEX Exchange Rate", passed, response)
        if passed:
            print(f"  Exchange Rate: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        log_test("DEX Exchange Rate", False, error=str(e))
    
    # 11. Test Latest Blocks
    try:
        response = requests.get(f"{API_URL}/blocks/latest")
        passed = response.status_code == 200
        log_test("Latest Blocks", passed, response)
        if passed:
            print(f"  Block count: {len(response.json())}")
    except Exception as e:
        log_test("Latest Blocks", False, error=str(e))
    
    # 12. Test Mining Info
    try:
        response = requests.get(f"{API_URL}/mining/info")
        passed = response.status_code == 200 and "current_reward" in response.json()
        log_test("Mining Info", passed, response)
        if passed:
            print(f"  Mining Info: {json.dumps(response.json(), indent=2)}")
    except Exception as e:
        log_test("Mining Info", False, error=str(e))
    
    # Print summary
    print("\n" + "="*50)
    print(f"SUMMARY: {test_results['passed']}/{test_results['total']} tests passed")
    print("="*50)
    
    if test_results["failed"] > 0:
        print("\nFailed tests:")
        for test in test_results["tests"]:
            if not test["passed"]:
                print(f"- {test['name']}")
    
    return test_results["failed"] == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)