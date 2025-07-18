# WEPO ENGINEERING TIPS & BEST PRACTICES

## 🎯 **CRITICAL IMPLEMENTATION LEARNINGS**

*Essential tips learned during the dynamic collateral system implementation and previous development cycles.*

---

## 🔧 **BLOCKCHAIN INTEGRATION PATTERNS**

### **Height-Based Calculations**
```python
# ✅ CORRECT: Always use block height for deterministic calculations
def get_requirement_for_height(height: int) -> int:
    for trigger_height in sorted(SCHEDULE.keys(), reverse=True):
        if height >= trigger_height:
            return SCHEDULE[trigger_height]
    return DEFAULT_VALUE

# ❌ WRONG: Never use timestamps or external data for core logic
def get_requirement_by_time():
    current_time = time.time()  # Non-deterministic!
    # This breaks consensus and causes network splits
```

### **Import Issue Solutions**
```python
# ❌ PROBLEM: Relative imports fail in blockchain modules
from .blockchain import WEPOBlockchain  # ImportError!
from blockchain import WEPOBlockchain   # ModuleNotFoundError!

# ✅ SOLUTION: Use hardcoded constants or direct implementation
COLLATERAL_SCHEDULE = {
    0: 10000,
    131400: 10000, 
    306600: 6000,
    # Direct implementation avoids import issues
}
```

### **Consensus Safety Patterns**
```python
# ✅ SAFE: Tie all adjustments to existing blockchain heights
DYNAMIC_SCHEDULE = {
    PRE_POS_DURATION_BLOCKS: 10000,     # Uses existing constant
    PHASE_2A_END_HEIGHT: 6000,          # Uses existing constant
    # Ensures consensus compatibility
}

# ❌ DANGEROUS: Creating new arbitrary heights
DYNAMIC_SCHEDULE = {
    100000: 8000,  # Arbitrary height - breaks consensus!
    200000: 6000,  # Not tied to existing system
}
```

---

## 🌐 **API DEVELOPMENT PATTERNS**

### **Consistent Error Handling**
```python
# ✅ STANDARD PATTERN: Use this for ALL endpoints
@app.get("/api/endpoint")
async def endpoint_handler():
    try:
        result = perform_operation()
        return {
            "success": True,
            "data": result,
            "timestamp": int(time.time())
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "timestamp": int(time.time())
        }
```

### **Port Configuration Management**
```bash
# 🔍 DISCOVERY: Different backends run on different ports
WepoFastTestBridge: http://localhost:8001  # Main test bridge
Backend Server:     http://localhost:8003  # Alternative backend

# ✅ TESTING TIP: Always verify which backend is active
curl http://localhost:8001/api/mining/info  # Test bridge availability
ps aux | grep python | grep bridge         # Check running processes
```

### **Data Validation Patterns**
```python
# ✅ ROBUST VALIDATION: Always validate critical data
def validate_collateral_data(data):
    required_fields = ['block_height', 'masternode_collateral_wepo', 'pos_collateral_wepo']
    
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
    
    if data['block_height'] < 0:
        raise ValueError("Block height cannot be negative")
    
    return True
```

---

## ⚛️ **FRONTEND DEVELOPMENT PATTERNS**

### **React Context Management**
```javascript
// ✅ PROPER CONTEXT UPDATE: Always sync all storage layers
const handleWalletUpdate = (walletData) => {
    // Update React context
    setWallet(walletData);
    
    // Update session storage
    sessionStorage.setItem('wepo_current_wallet', JSON.stringify(walletData));
    
    // Update local storage if needed
    localStorage.setItem('wepo_wallet', JSON.stringify(walletData));
    
    console.log('✅ Wallet context fully synchronized');
};

// ❌ BROKEN PATTERN: Only updating one layer
const handleBrokenUpdate = (walletData) => {
    setWallet(walletData);  // Only updates React context
    // Session/localStorage out of sync = authentication failures!
};
```

### **Async State Management**
```javascript
// ✅ PROPER ASYNC HANDLING: Always handle loading states
const [loading, setLoading] = useState(false);
const [error, setError] = useState(null);

const fetchData = async () => {
    setLoading(true);
    setError(null);
    
    try {
        const response = await fetch('/api/endpoint');
        const data = await response.json();
        
        if (data.success) {
            setData(data.data);
        } else {
            setError(data.error);
        }
    } catch (err) {
        setError('Network error: ' + err.message);
    } finally {
        setLoading(false);
    }
};
```

### **Component Initialization Patterns**
```javascript
// ✅ SAFE INITIALIZATION: Handle all possible states
useEffect(() => {
    const initializeComponent = async () => {
        try {
            // Check session first
            const sessionActive = sessionStorage.getItem('wepo_session_active');
            const sessionWallet = sessionStorage.getItem('wepo_current_wallet');
            
            if (sessionActive && sessionWallet) {
                const walletData = JSON.parse(sessionWallet);
                setWallet(walletData);
                setCurrentView('dashboard');
                console.log('✅ Session restored:', walletData.username);
                return;
            }
            
            // Check local storage
            const walletExists = localStorage.getItem('wepo_wallet_exists');
            if (walletExists) {
                setCurrentView('login');
                return;
            }
            
            // Default to setup
            setCurrentView('setup');
            
        } catch (error) {
            console.error('Initialization error:', error);
            setCurrentView('setup');  // Safe fallback
        } finally {
            setIsInitialized(true);
        }
    };

    initializeComponent();
}, []);
```

---

## 🧪 **TESTING STRATEGIES**

### **Boundary Testing for Dynamic Systems**
```python
# ✅ COMPREHENSIVE BOUNDARY TESTS
def test_collateral_boundaries():
    test_cases = [
        # (height, expected_mn, expected_pos, description)
        (0, 10000, 0, "Genesis block"),
        (131399, 10000, 0, "Just before PoS activation"),
        (131400, 10000, 1000, "PoS activation block"),
        (306599, 10000, 1000, "Just before 2nd halving"),
        (306600, 6000, 600, "2nd halving block"),
        (306601, 6000, 600, "Just after 2nd halving"),
    ]
    
    for height, exp_mn, exp_pos, desc in test_cases:
        actual_mn = get_masternode_collateral(height) / COIN
        actual_pos = get_pos_collateral(height) / COIN
        
        assert actual_mn == exp_mn, f"{desc}: MN {actual_mn} != {exp_mn}"
        assert actual_pos == exp_pos, f"{desc}: PoS {actual_pos} != {exp_pos}"
```

### **Percentage Verification**
```python
# ✅ MATHEMATICAL VALIDATION: Always verify percentages
def test_reduction_percentages():
    reductions = [
        (10000, 6000, 40.0),   # 2nd halving
        (6000, 3000, 50.0),    # 3rd halving  
        (3000, 1500, 50.0),    # 4th halving
        (1500, 1000, 33.33),   # 5th halving
    ]
    
    for old, new, expected_pct in reductions:
        actual_pct = ((old - new) / old) * 100
        tolerance = 0.1
        
        assert abs(actual_pct - expected_pct) < tolerance, \
            f"Reduction {old}→{new}: expected {expected_pct}%, got {actual_pct:.2f}%"
```

### **API Response Validation**
```python
# ✅ COMPLETE API TESTING: Validate structure and data
def test_api_response_structure():
    response = requests.get('/api/collateral/requirements')
    assert response.status_code == 200
    
    data = response.json()
    assert data['success'] == True
    assert 'data' in data
    assert 'timestamp' in data
    
    collateral_data = data['data']
    required_fields = [
        'block_height', 'masternode_collateral_wepo', 
        'pos_collateral_wepo', 'pos_available', 'phase'
    ]
    
    for field in required_fields:
        assert field in collateral_data, f"Missing field: {field}"
```

---

## 🛡️ **SECURITY BEST PRACTICES**

### **Input Validation Patterns**
```python
# ✅ STRICT VALIDATION: Always validate and sanitize inputs
def validate_height_input(height):
    if not isinstance(height, int):
        raise TypeError(f"Height must be integer, got {type(height)}")
    
    if height < 0:
        raise ValueError(f"Height cannot be negative: {height}")
    
    if height > MAX_REASONABLE_HEIGHT:  # e.g., 10M blocks
        raise ValueError(f"Height too large: {height}")
    
    return height

# ❌ DANGEROUS: No validation
def unsafe_function(height):
    return SCHEDULE[height]  # KeyError if height not in schedule!
```

### **Error Information Disclosure**
```python
# ✅ SAFE ERROR HANDLING: Don't expose internal details
try:
    result = sensitive_operation()
    return {"success": True, "data": result}
except DatabaseError as e:
    logger.error(f"Database error: {e}")
    return {"success": False, "error": "Internal system error"}
except ValidationError as e:
    return {"success": False, "error": f"Validation failed: {e}"}
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    return {"success": False, "error": "Unexpected system error"}

# ❌ DANGEROUS: Exposing internal details
except Exception as e:
    return {"success": False, "error": str(e)}  # May expose sensitive info!
```

---

## 🔍 **DEBUGGING TECHNIQUES**

### **Blockchain State Debugging**
```python
# ✅ DEBUGGING HELPERS: Add these during development
def debug_collateral_state(height):
    print(f"=== COLLATERAL DEBUG: Height {height} ===")
    
    mn_collateral = get_masternode_collateral_for_height(height)
    pos_collateral = get_pos_collateral_for_height(height)
    
    print(f"Masternode: {mn_collateral / COIN} WEPO")
    print(f"PoS: {pos_collateral / COIN} WEPO")
    print(f"PoS Available: {height >= POS_ACTIVATION_HEIGHT}")
    
    # Find current phase
    for trigger_height in sorted(SCHEDULE.keys(), reverse=True):
        if height >= trigger_height:
            print(f"Current Phase Trigger: Block {trigger_height}")
            break
    
    # Find next phase
    for trigger_height in sorted(SCHEDULE.keys()):
        if height < trigger_height:
            blocks_until = trigger_height - height
            print(f"Next Phase: Block {trigger_height} ({blocks_until} blocks)")
            break
    
    print("=" * 40)
```

### **API Debugging Patterns**
```python
# ✅ REQUEST/RESPONSE LOGGING: Essential for API debugging
import logging
import time

def log_api_call(endpoint, params=None, response=None):
    logger.info(f"API Call: {endpoint}")
    if params:
        logger.info(f"Parameters: {params}")
    if response:
        logger.info(f"Response: {response}")
    logger.info(f"Timestamp: {time.time()}")

# Usage in endpoints
@app.get("/api/collateral/requirements")
async def get_collateral_requirements():
    start_time = time.time()
    
    try:
        result = calculate_requirements()
        
        log_api_call("/api/collateral/requirements", 
                    params=None, response=result)
        
        return {"success": True, "data": result}
    except Exception as e:
        logger.error(f"API Error: {e}")
        return {"success": False, "error": str(e)}
    finally:
        duration = time.time() - start_time
        logger.info(f"API Duration: {duration:.3f}s")
```

---

## 📊 **PERFORMANCE OPTIMIZATION**

### **Efficient Lookup Patterns**
```python
# ✅ OPTIMIZED: Cache frequently accessed calculations
class CollateralCache:
    def __init__(self):
        self._cache = {}
    
    def get_collateral(self, height):
        if height in self._cache:
            return self._cache[height]
        
        result = self._calculate_collateral(height)
        self._cache[height] = result
        return result
    
    def _calculate_collateral(self, height):
        # Expensive calculation only done once per height
        pass

# Global cache instance
collateral_cache = CollateralCache()
```

### **Batch Operations**
```python
# ✅ EFFICIENT: Process multiple heights at once
def get_collateral_range(start_height, end_height):
    results = {}
    
    # Pre-sort schedule keys once
    sorted_keys = sorted(SCHEDULE.keys(), reverse=True)
    
    for height in range(start_height, end_height + 1):
        # Reuse sorted keys for each height
        for trigger_height in sorted_keys:
            if height >= trigger_height:
                results[height] = SCHEDULE[trigger_height]
                break
    
    return results

# ❌ INEFFICIENT: Multiple individual calls
results = {}
for height in range(start_height, end_height + 1):
    results[height] = get_collateral(height)  # Sorts keys each time!
```

---

## 🔄 **SYSTEM INTEGRATION PATTERNS**

### **Service Restart Procedures**
```bash
# ✅ PROPER RESTART SEQUENCE: Order matters
sudo supervisorctl stop all
sudo supervisorctl start backend
sleep 2  # Allow backend to initialize
sudo supervisorctl start frontend
sleep 2  # Allow frontend to initialize  
sudo supervisorctl start mongodb
sudo supervisorctl start wepo-bridge

# Check all services
sudo supervisorctl status
```

### **Environment Variable Management**
```python
# ✅ SAFE ENV ACCESS: Always provide defaults and validate
import os

def get_config_value(key, default=None, required=False):
    value = os.environ.get(key, default)
    
    if required and value is None:
        raise RuntimeError(f"Required environment variable {key} not set")
    
    return value

# Usage
BRIDGE_PORT = get_config_value('WEPO_BRIDGE_PORT', '8001')
BACKEND_URL = get_config_value('REACT_APP_BACKEND_URL', required=True)
```

---

## 🎯 **COMMON MISTAKES TO AVOID**

### **1. Import Hell**
```python
# ❌ WRONG: Complex relative imports
from ..core.blockchain import WEPOBlockchain
from ...utils.helpers import calculate_something

# ✅ RIGHT: Simple direct implementations
CONSTANTS = {...}  # Define constants directly
def calculate_locally():  # Implement logic locally
```

### **2. Port Confusion**
```bash
# ❌ WRONG: Assuming port without checking
curl http://localhost:8001/api/endpoint  # May not be running

# ✅ RIGHT: Verify port first
ps aux | grep python | grep -E "(8001|8003)"
curl http://localhost:CORRECT_PORT/api/endpoint
```

### **3. State Synchronization Issues**
```javascript
// ❌ WRONG: Partial state updates
setWallet(newData);  // Only updates React state
// sessionStorage still has old data = authentication failures!

// ✅ RIGHT: Complete synchronization
const updateWalletCompletely = (newData) => {
    setWallet(newData);
    sessionStorage.setItem('wepo_current_wallet', JSON.stringify(newData));
    localStorage.setItem('wepo_wallet', JSON.stringify(newData));
    console.log('✅ All wallet state synchronized');
};
```

### **4. Error Handling Gaps**
```python
# ❌ WRONG: Assuming success
result = external_api_call()
return {"data": result}  # What if it failed?

# ✅ RIGHT: Always handle failures
try:
    result = external_api_call()
    return {"success": True, "data": result}
except ExternalAPIError as e:
    return {"success": False, "error": "External service unavailable"}
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    return {"success": False, "error": "Internal error"}
```

---

## 📚 **KNOWLEDGE TRANSFER CHECKLIST**

### **For New Engineers**
- [ ] Read this entire document
- [ ] Understand height-based calculation patterns
- [ ] Know the port configuration (8001 vs 8003)
- [ ] Understand React context synchronization requirements
- [ ] Review the dynamic collateral implementation
- [ ] Run the test suite to understand expected behavior
- [ ] Check backend logs when debugging API issues

### **For System Operations**
- [ ] Understand service restart sequence
- [ ] Know how to check running processes and ports
- [ ] Understand the testing protocol in `test_result.md`
- [ ] Know the difference between WepoFastTestBridge and Backend Server
- [ ] Understand environment variable requirements

### **For Security Reviews**
- [ ] Review input validation patterns
- [ ] Check error information disclosure
- [ ] Verify consensus-critical calculations
- [ ] Test boundary conditions
- [ ] Validate API response structures

---

## 🚀 **FUTURE ENGINEERING CONSIDERATIONS**

### **Scalability Preparations**
```python
# For future high-traffic scenarios
class CollateralService:
    def __init__(self):
        self.cache = LRUCache(maxsize=10000)
        self.metrics = CollateralMetrics()
    
    async def get_collateral_async(self, height):
        # Non-blocking collateral calculation
        return await asyncio.create_task(self._calculate(height))
```

### **Monitoring Integration**
```python
# For production monitoring
def track_collateral_metrics(height, collateral):
    metrics.track_histogram('collateral.value', collateral)
    metrics.track_counter('collateral.requests', tags={'height': height})
    
    if collateral < ALERT_THRESHOLD:
        alerts.send_alert('Low collateral detected', severity='warning')
```

### **Database Integration**
```python
# For persistent collateral history
class CollateralHistory:
    def save_adjustment(self, height, old_value, new_value):
        record = {
            'height': height,
            'old_collateral': old_value,
            'new_collateral': new_value,
            'timestamp': time.time(),
            'reduction_pct': ((old_value - new_value) / old_value) * 100
        }
        db.collateral_history.insert_one(record)
```

---

**Created**: January 2025  
**Based on**: Dynamic Collateral System Implementation  
**Purpose**: Knowledge transfer and best practices  
**Audience**: Current and future WEPO engineers  
**Status**: Living document - update with new learnings