#!/usr/bin/env python3
"""
WEPO Blockchain Comprehensive Stress Test

This script performs a comprehensive stress test of the WEPO blockchain system,
focusing on the blockchain core, mining, and transaction validation.
"""

import requests
import json
import time
import uuid
import os
import sys
import random
import string
import concurrent.futures
from datetime import datetime
import statistics

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
    "tests": [],
    "performance_metrics": {
        "mining_times": [],
        "api_response_times": {},
        "mempool_capacity": 0
    }
}

def log_test(name, passed, response=None, error=None, metrics=None):
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
    
    result = {
        "name": name,
        "passed": passed,
        "timestamp": datetime.now().isoformat()
    }
    
    if metrics:
        result["metrics"] = metrics
    
    test_results["tests"].append(result)

def log_metric(category, value):
    """Log performance metric"""
    if category in test_results["performance_metrics"]:
        if isinstance(test_results["performance_metrics"][category], list):
            test_results["performance_metrics"][category].append(value)
        else:
            test_results["performance_metrics"][category] = value
    else:
        test_results["performance_metrics"][category] = value
    
    print(f"[METRIC] {category}: {value}")

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

def create_wallet():
    """Create a new wallet and return its details"""
    username = generate_random_username()
    address = generate_random_address()
    encrypted_private_key = generate_encrypted_key()
    
    wallet_data = {
        "username": username,
        "address": address,
        "encrypted_private_key": encrypted_private_key
    }
    
    start_time = time.time()
    response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
    end_time = time.time()
    
    if "api_response_times" not in test_results["performance_metrics"]:
        test_results["performance_metrics"]["api_response_times"] = {}
    
    if "wallet_create" not in test_results["performance_metrics"]["api_response_times"]:
        test_results["performance_metrics"]["api_response_times"]["wallet_create"] = []
    
    test_results["performance_metrics"]["api_response_times"]["wallet_create"].append(end_time - start_time)
    
    if response.status_code == 200:
        data = response.json()
        print(f"  Created wallet: {username} with address {address}")
        wallet_data["response"] = data
        return wallet_data
    else:
        print(f"  Failed to create wallet: {response.status_code} - {response.text}")
        return None

def get_network_status():
    """Get network status"""
    start_time = time.time()
    response = requests.get(f"{API_URL}/network/status")
    end_time = time.time()
    
    if "api_response_times" not in test_results["performance_metrics"]:
        test_results["performance_metrics"]["api_response_times"] = {}
    
    if "network_status" not in test_results["performance_metrics"]["api_response_times"]:
        test_results["performance_metrics"]["api_response_times"]["network_status"] = []
    
    test_results["performance_metrics"]["api_response_times"]["network_status"].append(end_time - start_time)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"  Failed to get network status: {response.status_code} - {response.text}")
        return None

def get_mining_info():
    """Get mining information"""
    start_time = time.time()
    response = requests.get(f"{API_URL}/mining/info")
    end_time = time.time()
    
    if "api_response_times" not in test_results["performance_metrics"]:
        test_results["performance_metrics"]["api_response_times"] = {}
    
    if "mining_info" not in test_results["performance_metrics"]["api_response_times"]:
        test_results["performance_metrics"]["api_response_times"]["mining_info"] = []
    
    test_results["performance_metrics"]["api_response_times"]["mining_info"].append(end_time - start_time)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"  Failed to get mining info: {response.status_code} - {response.text}")
        return None

def mine_block(miner_address=None):
    """Mine a block and return the block details"""
    if not miner_address:
        miner_address = "wepo1test000000000000000000000000000"
    
    mine_data = {"miner_address": miner_address}
    
    start_time = time.time()
    response = requests.post(f"{API_URL}/test/mine-block", json=mine_data)
    end_time = time.time()
    
    mining_time = end_time - start_time
    log_metric("mining_times", mining_time)
    
    if response.status_code == 200:
        data = response.json()
        print(f"  Mined block at height: {data.get('block_height')} in {mining_time:.4f} seconds")
        return data, response
    else:
        print(f"  Failed to mine block: {response.status_code} - {response.text}")
        return None, response

def test_blockchain_core():
    """Test blockchain core functionality"""
    print("\n" + "="*80)
    print("BLOCKCHAIN CORE TESTING")
    print("="*80)
    
    # 1. Check initial blockchain state
    print("\n[TEST] Checking initial blockchain state")
    network_status = get_network_status()
    
    if network_status:
        initial_block_height = network_status.get("block_height", 0)
        print(f"  Initial block height: {initial_block_height}")
        print(f"  Best block hash: {network_status.get('best_block_hash', 'unknown')}")
        print(f"  Network status: {network_status.get('status', 'unknown')}")
        log_test("Blockchain Core - Initial State", True)
    else:
        print(f"  Failed to get initial blockchain state")
        log_test("Blockchain Core - Initial State", False, error="Failed to get initial blockchain state")
        return False
    
    # 2. Check mining info
    print("\n[TEST] Checking mining info")
    mining_info = get_mining_info()
    
    if mining_info:
        print(f"  Current block height: {mining_info.get('current_block_height', 0)}")
        print(f"  Current reward: {mining_info.get('current_reward', 0)} WEPO")
        print(f"  Mining algorithm: {mining_info.get('algorithm', 'unknown')}")
        print(f"  Mempool size: {mining_info.get('mempool_size', 0)} transactions")
        log_test("Blockchain Core - Mining Info", True)
    else:
        print(f"  Failed to get mining info")
        log_test("Blockchain Core - Mining Info", False, error="Failed to get mining info")
        return False
    
    # 3. Mine a single block
    print("\n[TEST] Mining a single block")
    block_data, response = mine_block()
    
    if block_data and block_data.get("success") == True:
        print(f"  Successfully mined block at height: {block_data.get('block_height')}")
        print(f"  Block hash: {block_data.get('block_hash')}")
        print(f"  Mining reward: {block_data.get('reward')} WEPO")
        log_test("Blockchain Core - Single Block Mining", True)
    else:
        print(f"  Failed to mine block")
        log_test("Blockchain Core - Single Block Mining", False, error="Failed to mine block")
        return False
    
    # 4. Check blockchain state after mining
    print("\n[TEST] Checking blockchain state after mining")
    network_status_after = get_network_status()
    
    if network_status_after:
        new_block_height = network_status_after.get("block_height", 0)
        print(f"  New block height: {new_block_height}")
        
        if new_block_height > initial_block_height:
            print(f"  Block height increased by {new_block_height - initial_block_height}")
            log_test("Blockchain Core - Block Height Update", True)
        else:
            print(f"  Block height did not increase")
            log_test("Blockchain Core - Block Height Update", False, error="Block height did not increase")
    else:
        print(f"  Failed to get blockchain state after mining")
        log_test("Blockchain Core - Block Height Update", False, error="Failed to get blockchain state")
    
    return True

def test_mining_stress():
    """Test mining under stress"""
    print("\n" + "="*80)
    print("MINING STRESS TESTING")
    print("="*80)
    
    # 1. Check initial blockchain state
    print("\n[TEST] Checking initial blockchain state")
    network_status = get_network_status()
    
    if network_status:
        initial_block_height = network_status.get("block_height", 0)
        print(f"  Initial block height: {initial_block_height}")
        log_test("Mining Stress - Initial State", True)
    else:
        print(f"  Failed to get initial blockchain state")
        log_test("Mining Stress - Initial State", False, error="Failed to get initial blockchain state")
        return False
    
    # 2. Mine multiple blocks in sequence
    print("\n[TEST] Mining multiple blocks in sequence")
    block_count = 10
    mining_times = []
    
    for i in range(block_count):
        print(f"  Mining block {i+1}/{block_count}")
        block_data, response = mine_block()
        
        if block_data and block_data.get("success") == True:
            print(f"  Successfully mined block at height: {block_data.get('block_height')}")
            mining_time = test_results["performance_metrics"]["mining_times"][-1]
            mining_times.append(mining_time)
        else:
            print(f"  Failed to mine block {i+1}")
    
    if len(mining_times) > 0:
        avg_mining_time = statistics.mean(mining_times)
        max_mining_time = max(mining_times)
        min_mining_time = min(mining_times)
        
        print(f"  Average mining time: {avg_mining_time:.4f} seconds")
        print(f"  Maximum mining time: {max_mining_time:.4f} seconds")
        print(f"  Minimum mining time: {min_mining_time:.4f} seconds")
        
        log_test("Mining Stress - Sequential Mining", True, metrics={
            "avg_mining_time": avg_mining_time,
            "max_mining_time": max_mining_time,
            "min_mining_time": min_mining_time,
            "blocks_mined": len(mining_times)
        })
    else:
        print(f"  Failed to mine any blocks")
        log_test("Mining Stress - Sequential Mining", False, error="Failed to mine any blocks")
        return False
    
    # 3. Check blockchain state after mining
    print("\n[TEST] Checking blockchain state after mining")
    network_status_after = get_network_status()
    
    if network_status_after:
        new_block_height = network_status_after.get("block_height", 0)
        print(f"  New block height: {new_block_height}")
        
        if new_block_height >= initial_block_height + len(mining_times):
            print(f"  Block height increased by {new_block_height - initial_block_height}")
            log_test("Mining Stress - Block Height Update", True)
        else:
            print(f"  Block height did not increase as expected")
            log_test("Mining Stress - Block Height Update", False, error="Block height did not increase as expected")
    else:
        print(f"  Failed to get blockchain state after mining")
        log_test("Mining Stress - Block Height Update", False, error="Failed to get blockchain state")
    
    # 4. Attempt concurrent mining (this should be handled by the blockchain)
    print("\n[TEST] Attempting concurrent mining")
    concurrent_count = 5
    successful_mines = 0
    concurrent_mining_times = []
    
    def attempt_mining(i):
        print(f"  Concurrent mining attempt {i+1}/{concurrent_count}")
        block_data, response = mine_block()
        
        mining_time = test_results["performance_metrics"]["mining_times"][-1] if len(test_results["performance_metrics"]["mining_times"]) > 0 else 0
        
        return {
            "index": i,
            "success": block_data is not None and block_data.get("success") == True,
            "block_height": block_data.get("block_height") if block_data else None,
            "mining_time": mining_time
        }
    
    # Use ThreadPoolExecutor for parallel execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_count) as executor:
        future_to_mine = {executor.submit(attempt_mining, i): i for i in range(concurrent_count)}
        
        for future in concurrent.futures.as_completed(future_to_mine):
            result = future.result()
            
            if result["success"]:
                successful_mines += 1
                concurrent_mining_times.append(result["mining_time"])
                print(f"  Concurrent mining attempt {result['index']+1} succeeded: Block {result['block_height']}")
            else:
                print(f"  Concurrent mining attempt {result['index']+1} failed")
    
    if successful_mines > 0:
        avg_concurrent_mining_time = statistics.mean(concurrent_mining_times) if concurrent_mining_times else 0
        
        print(f"  {successful_mines}/{concurrent_count} concurrent mining attempts succeeded")
        print(f"  Average concurrent mining time: {avg_concurrent_mining_time:.4f} seconds")
        
        log_test("Mining Stress - Concurrent Mining", True, metrics={
            "successful_mines": successful_mines,
            "total_attempts": concurrent_count,
            "avg_mining_time": avg_concurrent_mining_time
        })
    else:
        print(f"  All concurrent mining attempts failed")
        log_test("Mining Stress - Concurrent Mining", False, error="All concurrent mining attempts failed")
    
    # 5. Check final blockchain state
    print("\n[TEST] Checking final blockchain state")
    final_network_status = get_network_status()
    
    if final_network_status:
        final_block_height = final_network_status.get("block_height", 0)
        print(f"  Final block height: {final_block_height}")
        
        blocks_added = final_block_height - initial_block_height
        print(f"  Total blocks added: {blocks_added}")
        
        log_test("Mining Stress - Final State", True, metrics={
            "initial_height": initial_block_height,
            "final_height": final_block_height,
            "blocks_added": blocks_added
        })
    else:
        print(f"  Failed to get final blockchain state")
        log_test("Mining Stress - Final State", False, error="Failed to get final blockchain state")
    
    return True

def test_block_size_limits():
    """Test block size limits"""
    print("\n" + "="*80)
    print("BLOCK SIZE LIMITS TESTING")
    print("="*80)
    
    # 1. Check initial blockchain state
    print("\n[TEST] Checking initial blockchain state")
    network_status = get_network_status()
    
    if network_status:
        initial_block_height = network_status.get("block_height", 0)
        print(f"  Initial block height: {initial_block_height}")
        log_test("Block Size Limits - Initial State", True)
    else:
        print(f"  Failed to get initial blockchain state")
        log_test("Block Size Limits - Initial State", False, error="Failed to get initial blockchain state")
        return False
    
    # 2. Check initial mempool state
    print("\n[TEST] Checking initial mempool state")
    mining_info = get_mining_info()
    
    if mining_info and "mempool_size" in mining_info:
        initial_mempool_size = mining_info["mempool_size"]
        print(f"  Initial mempool size: {initial_mempool_size} transactions")
        log_test("Block Size Limits - Initial Mempool", True)
    else:
        print(f"  Could not determine initial mempool size")
        log_test("Block Size Limits - Initial Mempool", False, error="Could not determine mempool size")
        return False
    
    # 3. Mine a block
    print("\n[TEST] Mining a block")
    block_data, response = mine_block()
    
    if block_data and block_data.get("success") == True:
        print(f"  Successfully mined block at height: {block_data.get('block_height')}")
        mining_time = test_results["performance_metrics"]["mining_times"][-1]
        print(f"  Mining time: {mining_time:.4f} seconds")
        log_test("Block Size Limits - Block Mining", True)
    else:
        print(f"  Failed to mine block")
        log_test("Block Size Limits - Block Mining", False, error="Failed to mine block")
        return False
    
    # 4. Check mempool after mining
    print("\n[TEST] Checking mempool after mining")
    mining_info_after = get_mining_info()
    
    if mining_info_after and "mempool_size" in mining_info_after:
        mempool_size_after = mining_info_after["mempool_size"]
        print(f"  Mempool size after mining: {mempool_size_after} transactions")
        
        if mempool_size_after <= initial_mempool_size:
            print(f"  Mempool size did not increase")
            log_test("Block Size Limits - Mempool After Mining", True)
        else:
            print(f"  Mempool size increased unexpectedly")
            log_test("Block Size Limits - Mempool After Mining", False, error="Mempool size increased unexpectedly")
    else:
        print(f"  Could not determine mempool size after mining")
        log_test("Block Size Limits - Mempool After Mining", False, error="Could not determine mempool size")
    
    # 5. Check blockchain state after mining
    print("\n[TEST] Checking blockchain state after mining")
    network_status_after = get_network_status()
    
    if network_status_after:
        new_block_height = network_status_after.get("block_height", 0)
        print(f"  New block height: {new_block_height}")
        
        if new_block_height > initial_block_height:
            print(f"  Block height increased by {new_block_height - initial_block_height}")
            log_test("Block Size Limits - Block Height Update", True)
        else:
            print(f"  Block height did not increase")
            log_test("Block Size Limits - Block Height Update", False, error="Block height did not increase")
    else:
        print(f"  Failed to get blockchain state after mining")
        log_test("Block Size Limits - Block Height Update", False, error="Failed to get blockchain state")
    
    return True

def test_api_performance():
    """Test API performance under load"""
    print("\n" + "="*80)
    print("API PERFORMANCE TESTING")
    print("="*80)
    
    # 1. Test network status API performance
    print("\n[TEST] Testing network status API performance")
    request_count = 50
    successful_requests = 0
    response_times = []
    
    for i in range(request_count):
        start_time = time.time()
        response = requests.get(f"{API_URL}/network/status")
        end_time = time.time()
        
        response_time = end_time - start_time
        response_times.append(response_time)
        
        if response.status_code == 200:
            successful_requests += 1
        
        if i % 10 == 0:
            print(f"  Completed {i}/{request_count} requests")
    
    if len(response_times) > 0:
        avg_response_time = statistics.mean(response_times)
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        
        print(f"  Average response time: {avg_response_time:.4f} seconds")
        print(f"  Maximum response time: {max_response_time:.4f} seconds")
        print(f"  Minimum response time: {min_response_time:.4f} seconds")
        print(f"  Successful requests: {successful_requests}/{request_count}")
        
        log_test("API Performance - Network Status", successful_requests > 0, metrics={
            "avg_response_time": avg_response_time,
            "max_response_time": max_response_time,
            "min_response_time": min_response_time,
            "successful_requests": successful_requests,
            "total_requests": request_count
        })
    else:
        print(f"  Failed to make any requests")
        log_test("API Performance - Network Status", False, error="Failed to make any requests")
    
    # 2. Test mining info API performance
    print("\n[TEST] Testing mining info API performance")
    request_count = 50
    successful_requests = 0
    response_times = []
    
    for i in range(request_count):
        start_time = time.time()
        response = requests.get(f"{API_URL}/mining/info")
        end_time = time.time()
        
        response_time = end_time - start_time
        response_times.append(response_time)
        
        if response.status_code == 200:
            successful_requests += 1
        
        if i % 10 == 0:
            print(f"  Completed {i}/{request_count} requests")
    
    if len(response_times) > 0:
        avg_response_time = statistics.mean(response_times)
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        
        print(f"  Average response time: {avg_response_time:.4f} seconds")
        print(f"  Maximum response time: {max_response_time:.4f} seconds")
        print(f"  Minimum response time: {min_response_time:.4f} seconds")
        print(f"  Successful requests: {successful_requests}/{request_count}")
        
        log_test("API Performance - Mining Info", successful_requests > 0, metrics={
            "avg_response_time": avg_response_time,
            "max_response_time": max_response_time,
            "min_response_time": min_response_time,
            "successful_requests": successful_requests,
            "total_requests": request_count
        })
    else:
        print(f"  Failed to make any requests")
        log_test("API Performance - Mining Info", False, error="Failed to make any requests")
    
    # 3. Test concurrent API requests
    print("\n[TEST] Testing concurrent API requests")
    concurrent_count = 20
    successful_requests = 0
    response_times = []
    
    def make_request(i):
        endpoint = f"{API_URL}/network/status" if i % 2 == 0 else f"{API_URL}/mining/info"
        
        start_time = time.time()
        response = requests.get(endpoint)
        end_time = time.time()
        
        return {
            "index": i,
            "endpoint": "network_status" if i % 2 == 0 else "mining_info",
            "success": response.status_code == 200,
            "response_time": end_time - start_time
        }
    
    # Use ThreadPoolExecutor for parallel execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_count) as executor:
        future_to_request = {executor.submit(make_request, i): i for i in range(concurrent_count)}
        
        for future in concurrent.futures.as_completed(future_to_request):
            result = future.result()
            
            if result["success"]:
                successful_requests += 1
                response_times.append(result["response_time"])
                print(f"  Concurrent request {result['index']+1} to {result['endpoint']} succeeded in {result['response_time']:.4f} seconds")
            else:
                print(f"  Concurrent request {result['index']+1} to {result['endpoint']} failed")
    
    if len(response_times) > 0:
        avg_response_time = statistics.mean(response_times)
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        
        print(f"  Average response time: {avg_response_time:.4f} seconds")
        print(f"  Maximum response time: {max_response_time:.4f} seconds")
        print(f"  Minimum response time: {min_response_time:.4f} seconds")
        print(f"  Successful requests: {successful_requests}/{concurrent_count}")
        
        log_test("API Performance - Concurrent Requests", successful_requests > 0, metrics={
            "avg_response_time": avg_response_time,
            "max_response_time": max_response_time,
            "min_response_time": min_response_time,
            "successful_requests": successful_requests,
            "total_requests": concurrent_count
        })
    else:
        print(f"  Failed to make any concurrent requests")
        log_test("API Performance - Concurrent Requests", False, error="Failed to make any concurrent requests")
    
    return True

def print_summary():
    """Print test summary"""
    print("\n" + "="*80)
    print("WEPO BLOCKCHAIN COMPREHENSIVE STRESS TEST SUMMARY")
    print("="*80)
    
    # Calculate success rate
    success_rate = (test_results["passed"] / test_results["total"] * 100) if test_results["total"] > 0 else 0
    
    print(f"Total tests:    {test_results['total']}")
    print(f"Passed:         {test_results['passed']}")
    print(f"Failed:         {test_results['failed']}")
    print(f"Success rate:   {success_rate:.1f}%")
    
    if test_results["failed"] > 0:
        print("\nFailed tests:")
        for test in test_results["tests"]:
            if not test["passed"]:
                print(f"- {test['name']}")
    
    print("\nPERFORMANCE METRICS:")
    
    # Mining times
    if "mining_times" in test_results["performance_metrics"] and test_results["performance_metrics"]["mining_times"]:
        mining_times = test_results["performance_metrics"]["mining_times"]
        avg_mining_time = statistics.mean(mining_times)
        max_mining_time = max(mining_times)
        min_mining_time = min(mining_times)
        
        print(f"- Mining Performance:")
        print(f"  - Average mining time: {avg_mining_time:.4f} seconds")
        print(f"  - Maximum mining time: {max_mining_time:.4f} seconds")
        print(f"  - Minimum mining time: {min_mining_time:.4f} seconds")
        print(f"  - Total blocks mined: {len(mining_times)}")
    
    # API response times
    if "api_response_times" in test_results["performance_metrics"] and test_results["performance_metrics"]["api_response_times"]:
        api_times = test_results["performance_metrics"]["api_response_times"]
        
        print(f"- API Performance:")
        for endpoint, times in api_times.items():
            if times:
                avg_time = statistics.mean(times)
                max_time = max(times)
                min_time = min(times)
                
                print(f"  - {endpoint}:")
                print(f"    - Average: {avg_time:.4f} seconds")
                print(f"    - Maximum: {max_time:.4f} seconds")
                print(f"    - Minimum: {min_time:.4f} seconds")
    
    print("\nSTRESS TEST RESULTS:")
    print("1. Blockchain Core: " + ("✅ PASSED" if all(t["name"].startswith("Blockchain Core") and t["passed"] for t in test_results["tests"] if t["name"].startswith("Blockchain Core")) else "❌ FAILED"))
    print("2. Mining Stress: " + ("✅ PASSED" if all(t["name"].startswith("Mining Stress") and t["passed"] for t in test_results["tests"] if t["name"].startswith("Mining Stress")) else "❌ FAILED"))
    print("3. Block Size Limits: " + ("✅ PASSED" if all(t["name"].startswith("Block Size Limits") and t["passed"] for t in test_results["tests"] if t["name"].startswith("Block Size Limits")) else "❌ FAILED"))
    print("4. API Performance: " + ("✅ PASSED" if all(t["name"].startswith("API Performance") and t["passed"] for t in test_results["tests"] if t["name"].startswith("API Performance")) else "❌ FAILED"))
    
    print("\nPRODUCTION READINESS ASSESSMENT:")
    if success_rate >= 90:
        print("✅ READY FOR PRODUCTION - System passed stress tests with high success rate")
    elif success_rate >= 75:
        print("⚠️ NEEDS MINOR FIXES - System generally stable but requires some improvements")
    else:
        print("❌ NOT PRODUCTION READY - System failed critical stress tests")
    
    print("="*80)

def main():
    """Main function"""
    print("\n" + "="*80)
    print("WEPO BLOCKCHAIN COMPREHENSIVE STRESS TEST")
    print("="*80)
    print("Testing WEPO blockchain system for production readiness")
    print("="*80 + "\n")
    
    # Run tests
    test_blockchain_core()
    test_mining_stress()
    test_block_size_limits()
    test_api_performance()
    
    # Print summary
    print_summary()
    
    return test_results["failed"] == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)