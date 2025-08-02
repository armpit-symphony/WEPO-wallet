#!/usr/bin/env python3
"""
WEPO BACKEND TESTING - SPECIFIC ISSUES INVESTIGATION

**ISSUES TO INVESTIGATE:**

**1. PoS Collateral System Verification**
- Check if the original WEPO PoS collateral requirements are accessible via API
- Test endpoints like `/api/pos/collateral`, `/api/staking/requirements`, `/api/blockchain/collateral`
- Verify the dynamic schedule: 1,000→600→300→150→100 WEPO based on halving phases

**2. Liquidity Addition HTTP 500 Error**
- Test POST `/api/liquidity/add` to reproduce the 'total_shares' error from previous testing
- Use valid test data to see the exact error message
- Previous testing showed: "HTTP 500 error with 'total_shares' but no bootstrap contamination"

**3. Masternode Collateral Verification**
- Check if there are endpoints to get current masternode collateral requirements
- Verify the dynamic schedule: 10,000→6,000→3,000→1,500→1,000 WEPO based on halving phases
- Test endpoints like `/api/masternode/collateral`, `/api/blockchain/masternode-requirements`

**4. Blockchain Integration Test**
- Check if blockchain.py collateral functions are accessible

**GOAL:** 
Provide comprehensive list of what's broken and needs fixing.
"""
import requests
import json
import time
import uuid
import os
import sys
import secrets
from datetime import datetime
import random
import string
import base64
import hashlib
import re

# Use preview backend URL from frontend/.env
BACKEND_URL = "https://130f3a1c-445d-47c5-ac8a-2b468eeb6e1f.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

print(f"🎯 WEPO BACKEND TESTING - SPECIFIC ISSUES INVESTIGATION")
print(f"Preview Backend API URL: {API_URL}")
print(f"Focus: Testing specific issues found in previous testing")
print("=" * 80)

# Test results tracking
test_results = {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "tests": []
}

def log_test(name, passed, response=None, error=None, details=None):
    """Log test results with enhanced details"""
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} {name}")
    
    if details:
        print(f"  Details: {details}")
    
    if error:
        print(f"  Error: {error}")
    
    if response and not passed:
        print(f"  Response: {response}")
    
    test_results["total"] += 1
    if passed:
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    test_results["tests"].append({
        "name": name,
        "passed": passed,
        "error": error,
        "details": details
    })

def generate_valid_wepo_address():
    """Generate a valid 37-character WEPO address (wepo1 + 32 hex chars)"""
    random_data = secrets.token_bytes(16)  # 16 bytes = 32 hex chars
    hex_part = random_data.hex()
    return f"wepo1{hex_part}"

def test_pos_collateral_system():
    """Test 1: PoS Collateral System Verification"""
    print("\n🎯 TEST 1: PoS COLLATERAL SYSTEM VERIFICATION")
    print("Testing PoS collateral requirements API endpoints...")
    
    pos_endpoints = [
        "/api/pos/collateral",
        "/api/staking/requirements", 
        "/api/blockchain/collateral",
        "/api/collateral/pos",
        "/api/staking/collateral"
    ]
    
    working_endpoints = []
    pos_data_found = False
    
    try:
        for endpoint in pos_endpoints:
            try:
                response = requests.get(f"{BACKEND_URL}{endpoint}")
                if response.status_code == 200:
                    data = response.json()
                    working_endpoints.append(endpoint)
                    
                    # Check for PoS collateral data
                    data_str = str(data).lower()
                    if any(term in data_str for term in ['pos', 'staking', 'collateral', '1000', '600', '300', '150', '100']):
                        pos_data_found = True
                        print(f"  ✅ {endpoint} - Found PoS data: {list(data.keys())[:5]}")
                    else:
                        print(f"  ⚠️  {endpoint} - No PoS collateral data")
                else:
                    print(f"  ❌ {endpoint} - HTTP {response.status_code}")
            except Exception as e:
                print(f"  ❌ {endpoint} - Error: {str(e)}")
        
        if working_endpoints and pos_data_found:
            log_test("PoS Collateral System", True, 
                    details=f"✅ Found {len(working_endpoints)} working endpoints with PoS data")
            return True
        elif working_endpoints:
            log_test("PoS Collateral System", False,
                    details=f"⚠️  Found {len(working_endpoints)} endpoints but no PoS collateral data")
            return False
        else:
            log_test("PoS Collateral System", False,
                    details="❌ No working PoS collateral endpoints found")
            return False
            
    except Exception as e:
        log_test("PoS Collateral System", False, error=str(e))
        return False

def test_liquidity_addition_http_500():
    """Test 2: Liquidity Addition HTTP 500 Error - Reproduce 'total_shares' error"""
    print("\n🎯 TEST 2: LIQUIDITY ADDITION HTTP 500 ERROR")
    print("Testing POST /api/liquidity/add to reproduce 'total_shares' error...")
    
    try:
        # Generate test wallet address
        test_wallet = generate_valid_wepo_address()
        
        # Test data from review request
        liquidity_data = {
            "wallet_address": test_wallet,
            "btc_amount": 0.01,
            "wepo_amount": 100.0
        }
        
        response = requests.post(f"{API_URL}/liquidity/add", json=liquidity_data)
        
        if response.status_code == 500:
            error_text = response.text
            if 'total_shares' in error_text.lower():
                log_test("Liquidity Addition HTTP 500", True,
                        details=f"✅ Reproduced 'total_shares' error: {error_text[:100]}...")
                return True
            else:
                log_test("Liquidity Addition HTTP 500", False,
                        details=f"❌ HTTP 500 but different error: {error_text[:100]}...")
                return False
        elif response.status_code == 200:
            log_test("Liquidity Addition HTTP 500", False,
                    details="❌ Request succeeded (HTTP 200) - error may be fixed")
            return False
        else:
            log_test("Liquidity Addition HTTP 500", False,
                    details=f"❌ Unexpected status code: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        log_test("Liquidity Addition HTTP 500", False, error=str(e))
        return False

def test_masternode_collateral_verification():
    """Test 3: Masternode Collateral Verification"""
    print("\n🎯 TEST 3: MASTERNODE COLLATERAL VERIFICATION")
    print("Testing masternode collateral requirements API endpoints...")
    
    masternode_endpoints = [
        "/api/masternode/collateral",
        "/api/blockchain/masternode-requirements",
        "/api/collateral/masternode",
        "/api/masternode/requirements",
        "/api/blockchain/collateral"
    ]
    
    working_endpoints = []
    masternode_data_found = False
    
    try:
        for endpoint in masternode_endpoints:
            try:
                response = requests.get(f"{BACKEND_URL}{endpoint}")
                if response.status_code == 200:
                    data = response.json()
                    working_endpoints.append(endpoint)
                    
                    # Check for masternode collateral data
                    data_str = str(data).lower()
                    if any(term in data_str for term in ['masternode', 'collateral', '10000', '6000', '3000', '1500', '1000']):
                        masternode_data_found = True
                        print(f"  ✅ {endpoint} - Found masternode data: {list(data.keys())[:5]}")
                    else:
                        print(f"  ⚠️  {endpoint} - No masternode collateral data")
                else:
                    print(f"  ❌ {endpoint} - HTTP {response.status_code}")
            except Exception as e:
                print(f"  ❌ {endpoint} - Error: {str(e)}")
        
        if working_endpoints and masternode_data_found:
            log_test("Masternode Collateral Verification", True, 
                    details=f"✅ Found {len(working_endpoints)} working endpoints with masternode data")
            return True
        elif working_endpoints:
            log_test("Masternode Collateral Verification", False,
                    details=f"⚠️  Found {len(working_endpoints)} endpoints but no masternode collateral data")
            return False
        else:
            log_test("Masternode Collateral Verification", False,
                    details="❌ No working masternode collateral endpoints found")
            return False
            
    except Exception as e:
        log_test("Masternode Collateral Verification", False, error=str(e))
        return False

def test_blockchain_integration():
    """Test 4: Blockchain Integration Test - Check if blockchain.py collateral functions are accessible"""
    print("\n🎯 TEST 4: BLOCKCHAIN INTEGRATION TEST")
    print("Testing blockchain.py collateral functions accessibility...")
    
    blockchain_endpoints = [
        "/api/blockchain/collateral",
        "/api/blockchain/status",
        "/api/network/status",
        "/api/collateral/requirements",
        "/api/blockchain/info"
    ]
    
    working_endpoints = []
    blockchain_data_found = False
    
    try:
        for endpoint in blockchain_endpoints:
            try:
                response = requests.get(f"{BACKEND_URL}{endpoint}")
                if response.status_code == 200:
                    data = response.json()
                    working_endpoints.append(endpoint)
                    
                    # Check for blockchain integration data
                    data_str = str(data).lower()
                    if any(term in data_str for term in ['blockchain', 'block', 'height', 'collateral', 'phase']):
                        blockchain_data_found = True
                        print(f"  ✅ {endpoint} - Found blockchain data: {list(data.keys())[:5]}")
                    else:
                        print(f"  ⚠️  {endpoint} - No blockchain integration data")
                else:
                    print(f"  ❌ {endpoint} - HTTP {response.status_code}")
            except Exception as e:
                print(f"  ❌ {endpoint} - Error: {str(e)}")
        
        if working_endpoints and blockchain_data_found:
            log_test("Blockchain Integration", True, 
                    details=f"✅ Found {len(working_endpoints)} working endpoints with blockchain data")
            return True
        elif working_endpoints:
            log_test("Blockchain Integration", False,
                    details=f"⚠️  Found {len(working_endpoints)} endpoints but no blockchain integration data")
            return False
        else:
            log_test("Blockchain Integration", False,
                    details="❌ No working blockchain integration endpoints found")
            return False
            
    except Exception as e:
        log_test("Blockchain Integration", False, error=str(e))
        return False

def run_specific_issues_testing():
    """Run specific issues testing"""
    print("🔍 STARTING WEPO SPECIFIC ISSUES INVESTIGATION")
    print("Testing specific issues found in previous testing that still need to be fixed...")
    print("=" * 80)
    
    # Run the specific issue tests
    test1_result = test_pos_collateral_system()
    test2_result = test_liquidity_addition_http_500()
    test3_result = test_masternode_collateral_verification()
    test4_result = test_blockchain_integration()
    
    # Print final results
    print("\n" + "=" * 80)
    print("🔍 WEPO SPECIFIC ISSUES INVESTIGATION RESULTS")
    print("=" * 80)
    
    success_rate = (test_results["passed"] / test_results["total"]) * 100 if test_results["total"] > 0 else 0
    
    print(f"Total Tests: {test_results['total']}")
    print(f"Passed: {test_results['passed']} ✅")
    print(f"Failed: {test_results['failed']} ❌")
    print(f"Overall Success Rate: {success_rate:.1f}%")
    
    # Specific Issues Areas
    print("\n🔍 SPECIFIC ISSUES AREAS:")
    specific_tests = [
        "PoS Collateral System",
        "Liquidity Addition HTTP 500", 
        "Masternode Collateral Verification",
        "Blockchain Integration"
    ]
    
    specific_passed = 0
    for test in test_results['tests']:
        if test['name'] in specific_tests and test['passed']:
            specific_passed += 1
            print(f"  ✅ {test['name']}")
        elif test['name'] in specific_tests:
            print(f"  ❌ {test['name']}")
    
    print(f"\nSpecific Issues Areas: {specific_passed}/{len(specific_tests)} passed")
    
    # Calculate actual success rate
    actual_success_rate = (specific_passed / len(specific_tests)) * 100
    
    print("\n📋 SPECIFIC ISSUES ANALYSIS:")
    print(f"{'✅' if test1_result else '❌'} PoS Collateral System - Original WEPO PoS collateral requirements API access")
    print(f"{'✅' if test2_result else '❌'} Liquidity Addition HTTP 500 - 'total_shares' error reproduction")
    print(f"{'✅' if test3_result else '❌'} Masternode Collateral Verification - Dynamic schedule API access")
    print(f"{'✅' if test4_result else '❌'} Blockchain Integration - blockchain.py collateral functions accessibility")
    
    # Detailed findings
    print("\n🚨 DETAILED FINDINGS:")
    
    failed_tests = [test for test in test_results['tests'] if not test['passed']]
    if failed_tests:
        print("❌ ISSUES THAT NEED FIXING:")
        for test in failed_tests:
            print(f"  • {test['name']}: {test['details'] or test['error']}")
    
    working_tests = [test for test in test_results['tests'] if test['passed']]
    if working_tests:
        print("✅ WORKING SYSTEMS:")
        for test in working_tests:
            print(f"  • {test['name']}: {test['details']}")
    
    return {
        "success_rate": actual_success_rate,
        "pos_collateral": test1_result,
        "liquidity_error": test2_result,
        "masternode_collateral": test3_result,
        "blockchain_integration": test4_result,
        "failed_tests": failed_tests,
        "working_tests": working_tests
    }

if __name__ == "__main__":
    # Run the specific issues investigation
    results = run_specific_issues_testing()
    
    print("\n" + "=" * 80)
    print("🎯 FINAL INVESTIGATION SUMMARY")
    print("=" * 80)
    
    if results["success_rate"] >= 75:
        print(f"🎉 MOST ISSUES RESOLVED!")
        print(f"✅ {results['success_rate']:.1f}% success rate achieved")
        print(f"✅ Most systems are working correctly")
    else:
        print(f"🚨 CRITICAL ISSUES STILL NEED FIXING!")
        print(f"⚠️  Success rate: {results['success_rate']:.1f}%")
        print(f"❌ Multiple systems require attention")
    
    print(f"\n📊 SYSTEM STATUS:")
    print(f"• PoS Collateral System: {'✅ WORKING' if results['pos_collateral'] else '❌ BROKEN'}")
    print(f"• Liquidity Addition: {'✅ ERROR REPRODUCED' if results['liquidity_error'] else '❌ CANNOT REPRODUCE ERROR'}")
    print(f"• Masternode Collateral: {'✅ WORKING' if results['masternode_collateral'] else '❌ BROKEN'}")
    print(f"• Blockchain Integration: {'✅ WORKING' if results['blockchain_integration'] else '❌ BROKEN'}")
    
    if results["failed_tests"]:
        print(f"\n🔧 PRIORITY FIXES NEEDED:")
        for i, test in enumerate(results["failed_tests"], 1):
            print(f"{i}. {test['name']}")
            print(f"   Issue: {test['details'] or test['error']}")