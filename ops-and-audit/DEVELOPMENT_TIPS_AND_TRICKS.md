# 🛠️ WEPO Development Tips & Tricks

## 🚀 **CRITICAL DEVELOPMENT GUIDELINES**

### **⚠️ MUST-READ BEFORE DEVELOPMENT:**

**1. Service Architecture (NEVER MODIFY):**
```bash
# These URLs are PROTECTED - DO NOT CHANGE:
frontend/.env: REACT_APP_BACKEND_URL (production-configured)  
backend/.env: MONGO_URL (configured for local MongoDB)

# Backend MUST bind to 0.0.0.0:8001 (supervisor handles external mapping)
# All backend API routes MUST be prefixed with '/api' for Kubernetes ingress
```

**2. Service Management:**
```bash
# Restart services correctly:
sudo supervisorctl restart frontend
sudo supervisorctl restart backend 
sudo supervisorctl restart wepo-bridge
sudo supervisorctl restart all

# Check service status:
sudo supervisorctl status

# View logs:
tail -n 20 /var/log/supervisor/frontend.err.log
tail -n 20 /var/log/supervisor/wepo-bridge.err.log
```

**3. Frontend Development:**
```bash
# Use yarn, NEVER npm (npm causes breaking changes)
cd /app/frontend && yarn install
cd /app/frontend && yarn dev

# Hot reload is enabled - only restart for .env changes or new dependencies
```

---

## 🔐 **BITCOIN INTEGRATION TIPS**

### **Current Bitcoin Architecture:**

**1. Bitcoin Network Service (`SelfCustodialBitcoinWallet.js`):**
```javascript
// BlockCypher API integration with rate limiting
const BLOCKCYPHER_API = {
  BASE_URL: 'https://api.blockcypher.com/v1/btc/main',  // MAINNET
  RATE_LIMIT: 350ms between requests (3/sec free tier)
}

// Key methods implemented:
- getAddressInfo(address)      // Get address details
- getAddressBalance(address)   // Get balance in satoshis  
- getUnspentOutputs(address)   // Get UTXOs for transactions
- broadcastTransaction(hexTx)  // Broadcast to Bitcoin network
```

**2. Wallet Context Integration:**
```javascript
// Bitcoin wallet initialized from WEPO seed phrase
const btcWallet = new SelfCustodialBitcoinWallet();
await btcWallet.initializeFromSeed(seedPhrase);

// Background balance sync (non-blocking)
btcWallet.syncBalancesInBackground();

// Balance updates every 30 seconds automatically
```

**3. Troubleshooting Bitcoin Issues:**
```javascript
// If Bitcoin wallet causes crashes, temporarily disable:
// In WalletContext.js, comment out:
// import SelfCustodialBitcoinWallet from '../utils/SelfCustodialBitcoinWallet';

// And use placeholder implementation until fixed
```

---

## 🏦 **MASTERNODE DEVELOPMENT TIPS**

### **Masternode Collateral System:**

**1. Dynamic Collateral Calculation:**
```python
# Backend: wepo-fast-test-bridge.py
def get_dynamic_masternode_collateral(block_height):
    base_collateral = 10000  # WEPO base requirement
    # Collateral adjusts based on network growth
    return base_collateral
```

**2. Privacy Mixing Architecture:**
```javascript
// Privacy mixing available to ALL users (not just masternode operators)
// Masternode operators: Provide mixing service, earn fees
// Regular users: Use mixing service, pay small fees
```

**3. Masternode Status Checking:**
```bash
# Check masternode eligibility:
curl "https://your-url/api/wallet/bitcoin-privacy-status?wallet_address=wepo1..."

# Response shows:
# - public_mode: Available to everyone
# - private_mode: Available when masternodes active  
# - masternode_opportunity: Can user run masternode?
```

---

## 🔧 **COMMON DEVELOPMENT ISSUES & SOLUTIONS**

### **1. Wallet Black Screen / Runtime Errors:**

**Problem:** React app shows black screen or runtime error
**Solution:**
```javascript
// Most common cause: Bitcoin wallet initialization crash
// Quick fix: Disable Bitcoin wallet temporarily
// In WalletContext.js:
const initializeBitcoinWallet = async (seedPhrase) => {
  // Temporary placeholder to prevent crashes
  setBtcBalance(0.0);
  setBtcAddresses([]);
  return { success: true, mode: 'placeholder' };
};
```

### **2. Frontend Build Errors:**

**Problem:** Frontend fails to compile
**Solution:**
```bash
# Check for syntax errors:
cd /app/frontend && npm run build

# Common fixes:
# - Missing semicolons in JavaScript
# - Unused imports (comment out)
# - Wrong import paths
# - ESLint errors in Bitcoin wallet files
```

### **3. Backend API Endpoints Not Working:**

**Problem:** 404 errors on API calls
**Solution:**
```bash
# Ensure wepo-bridge service is running (handles API):
sudo supervisorctl status wepo-bridge

# Check if endpoints are prefixed with /api:
curl "https://your-url/api/wallet/create"  # ✅ Correct
curl "https://your-url/wallet/create"      # ❌ Wrong (404)
```

### **4. MongoDB Connection Issues:**

**Problem:** Database connection errors
**Solution:**
```bash
# Check MongoDB service:
sudo supervisorctl status mongodb

# Verify MONGO_URL in backend/.env (DON'T MODIFY):
cat /app/backend/.env | grep MONGO_URL

# Common fix - restart backend after MongoDB issues:
sudo supervisorctl restart backend wepo-bridge
```

---

## 🧪 **TESTING & DEBUGGING TIPS**

### **1. Backend Testing:**
```bash
# Test wallet creation:
curl -X POST https://your-url/api/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"username":"test123","password":"SecurePass123!@#"}'

# Test Bitcoin privacy status:
curl "https://your-url/api/wallet/bitcoin-privacy-status?wallet_address=wepo1..."

# Test masternode collateral info:
curl "https://your-url/api/masternode/collateral-info"
```

### **2. Frontend Debugging:**
```javascript
// Add debugging to WalletContext.js:
console.log('🔐 Bitcoin wallet state:', {
  btcBalance,
  btcAddresses: btcAddresses.length,
  isLoading: isBtcLoading
});

// Check localStorage for wallet data:
console.log('💾 Stored wallet:', localStorage.getItem('wepo_wallet_exists'));
```

### **3. Browser Console Monitoring:**
```javascript
// Watch for common errors:
// - "SelfCustodialBitcoinWallet is not defined" 
// - "Cannot read property of undefined"
// - "Network request failed" (API issues)
// - CSP violations (Content Security Policy)
```

---

## 🚀 **PERFORMANCE OPTIMIZATION TIPS**

### **1. Bitcoin Balance Sync Optimization:**
```javascript
// Current: 30-second intervals for balance updates
// For production: Consider WebSocket connections for real-time updates
// For development: Increase interval to reduce API calls:

const balanceUpdateInterval = setInterval(async () => {
  // Update logic
}, 60000); // 60 seconds instead of 30
```

### **2. React Performance:**
```javascript
// Use React.memo for expensive components:
const Dashboard = React.memo(() => {
  // Component logic
});

// Debounce user inputs:
const debouncedSearch = useMemo(
  () => debounce((searchTerm) => {
    // Search logic
  }, 300),
  []
);
```

### **3. API Rate Limiting:**
```javascript
// BlockCypher free tier: 3 requests/sec, 200/hour
// Implement request batching for multiple addresses:
const batchAddressRequests = async (addresses) => {
  // Batch multiple addresses into single request where possible
  // Use address batch endpoint: /addrs/addr1;addr2;addr3
};
```

---

## 🔐 **SECURITY BEST PRACTICES**

### **1. Never Hardcode Sensitive Data:**
```javascript
// ❌ Wrong:
const API_KEY = "your-api-key-here";

// ✅ Correct:
const API_KEY = process.env.REACT_APP_API_KEY;
```

### **2. Input Validation:**
```javascript
// Always validate user inputs (already implemented):
// - Amount validation (positive, max 8 decimals, no scientific notation)
// - Address validation (37 characters, starts with "wepo1")
// - XSS protection (HTML sanitization)
```

### **3. Private Key Security:**
```javascript
// Bitcoin private keys are generated client-side only
// Never send private keys to server
// Use BIP39 seed phrase for deterministic generation
```

---

## 🎯 **DEPLOYMENT & PRODUCTION TIPS**

### **1. Environment Configuration:**
```bash
# Production checklist:
# ✅ REACT_APP_BACKEND_URL points to production API
# ✅ MongoDB connection string configured
# ✅ All services running under supervisor
# ✅ HTTPS enabled for all endpoints
# ✅ Bitcoin API keys configured (if using paid tier)
```

### **2. Monitoring & Logging:**
```bash
# Monitor service health:
watch -n 5 'sudo supervisorctl status'

# Monitor Bitcoin API usage:
tail -f /var/log/supervisor/wepo-bridge.out.log | grep -i bitcoin

# Monitor wallet creation:
tail -f /var/log/supervisor/wepo-bridge.out.log | grep -i wallet
```

### **3. Scaling Considerations:**
```javascript
// For high traffic:
// - Implement Redis for session management
// - Use Bitcoin Electrum servers for better performance
// - Add load balancing for multiple backend instances
// - Consider WebSocket connections for real-time updates
```

---

## 🔄 **DEVELOPMENT WORKFLOW**

### **1. Safe Development Process:**
```bash
# 1. Always backup working state:
git add . && git commit -m "Working state before changes"

# 2. Test changes in isolation:
# - Modify one component at a time
# - Test in browser after each change
# - Check browser console for errors

# 3. Service restart order:
sudo supervisorctl restart wepo-bridge  # Backend API
sudo supervisorctl restart frontend     # React app
```

### **2. Debugging Workflow:**
```bash
# 1. Check service status:
sudo supervisorctl status

# 2. Check logs for errors:
tail -n 50 /var/log/supervisor/frontend.err.log
tail -n 50 /var/log/supervisor/wepo-bridge.err.log

# 3. Test API endpoints manually:
curl -I https://your-url/api/

# 4. Check browser console for JavaScript errors
```

### **3. Feature Development:**
```bash
# 1. Start with backend API implementation
# 2. Test API with curl
# 3. Implement frontend integration
# 4. Test end-to-end functionality
# 5. Document changes in README.md
```

---

## 📚 **USEFUL COMMANDS REFERENCE**

### **Service Management:**
```bash
# Restart individual services:
sudo supervisorctl restart frontend
sudo supervisorctl restart backend
sudo supervisorctl restart wepo-bridge
sudo supervisorctl restart all

# Check service status:
sudo supervisorctl status

# View service configuration:
sudo supervisorctl avail
```

### **Debugging Commands:**
```bash
# View real-time logs:
tail -f /var/log/supervisor/frontend.out.log
tail -f /var/log/supervisor/wepo-bridge.out.log

# Check last 50 lines of error logs:
tail -n 50 /var/log/supervisor/frontend.err.log
tail -n 50 /var/log/supervisor/wepo-bridge.err.log

# Test API endpoints:
curl -X POST https://your-url/api/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test123!@#"}'
```

### **Frontend Development:**
```bash
# Install dependencies:
cd /app/frontend && yarn install

# Build for production:
cd /app/frontend && yarn build

# Check for build issues:
cd /app/frontend && npm run build 2>&1 | grep -i error
```

---

## ⚡ **QUICK FIXES FOR COMMON ISSUES**

### **Black Screen on Wallet:**
```bash
# 1. Check for JavaScript errors in browser console
# 2. Temporarily disable Bitcoin wallet initialization
# 3. Restart frontend service
sudo supervisorctl restart frontend
```

### **API 404 Errors:**
```bash
# 1. Ensure API routes have /api prefix
# 2. Check wepo-bridge service is running
sudo supervisorctl status wepo-bridge
# 3. Verify REACT_APP_BACKEND_URL is correct
```

### **Bitcoin Balance Not Updating:**
```javascript
// Check if background sync is running:
console.log('🔄 Bitcoin sync active:', btcWallet?.isInitialized);

// Manually trigger balance update:
if (btcWallet) {
  btcWallet.updateAllBalances();
}
```

---

## 🎯 **FUTURE DEVELOPMENT ROADMAP**

### **Next Priority Features:**
1. **Enhanced Bitcoin Transaction Broadcasting**
   - Full transaction creation and signing
   - Multi-input transaction support
   - Transaction fee optimization

2. **Advanced Masternode Features**  
   - Masternode dashboard and monitoring
   - Automated mixing service management
   - Fee distribution tracking

3. **Mobile App Development**
   - React Native implementation
   - Mobile-optimized mining interface
   - Push notifications for transactions

4. **Advanced Privacy Features**
   - Multi-round Bitcoin mixing
   - Coinjoin integration
   - Enhanced anonymity metrics

---

**💡 Remember: Always test changes thoroughly before deploying to production!**

**🚨 Critical: Never modify the protected environment variables (REACT_APP_BACKEND_URL, MONGO_URL)**

**🛡️ Security: Always validate user inputs and sanitize data before processing**