/**
 * WEPO Wallet Mining WebWorker
 * Browser-based Argon2 mining for wallet integration
 * Runs in background thread to avoid blocking UI
 */

// Import Argon2 library for browser
// Note: In production, you would import a proper Argon2 WASM library
// For now, we'll use a simplified hash function for demonstration

let mining = false;
let currentJob = null;
let hashCount = 0;
let startTime = Date.now();
let cpuUsage = 25; // Default 25% CPU usage

// Mining configuration
const HASH_BATCH_SIZE = 100; // Process 100 hashes per batch
const CPU_USAGE_DELAY = {
  25: 300,  // 25% CPU = 300ms delay between batches
  50: 150,  // 50% CPU = 150ms delay
  75: 50,   // 75% CPU = 50ms delay  
  100: 0    // 100% CPU = no delay
};

// Listen for messages from main thread
self.onmessage = function(e) {
  const { type, data } = e.data;
  
  switch (type) {
    case 'START_MINING':
      startMining(data);
      break;
    case 'STOP_MINING':
      stopMining();
      break;
    case 'UPDATE_JOB':
      updateJob(data);
      break;
    case 'SET_CPU_USAGE':
      setCpuUsage(data.cpuUsage);
      break;
  }
};

function startMining(jobData) {
  currentJob = jobData;
  mining = true;
  hashCount = 0;
  startTime = Date.now();
  
  postMessage({
    type: 'MINING_STARTED',
    data: { jobId: currentJob.job_id }
  });
  
  // Start mining loop
  mineLoop();
}

function stopMining() {
  mining = false;
  postMessage({
    type: 'MINING_STOPPED',
    data: { totalHashes: hashCount }
  });
}

function updateJob(jobData) {
  currentJob = jobData;
  postMessage({
    type: 'JOB_UPDATED',
    data: { jobId: currentJob.job_id }
  });
}

function setCpuUsage(newCpuUsage) {
  cpuUsage = newCpuUsage;
  postMessage({
    type: 'CPU_USAGE_UPDATED',
    data: { cpuUsage: cpuUsage }
  });
}

async function mineLoop() {
  while (mining && currentJob) {
    // Mine a batch of hashes
    const batchResult = await mineBatch();
    
    if (batchResult.solution) {
      // Found a solution!
      postMessage({
        type: 'SOLUTION_FOUND',
        data: {
          jobId: currentJob.job_id,
          nonce: batchResult.nonce,
          hash: batchResult.hash,
          totalHashes: hashCount
        }
      });
    }
    
    // Update hashrate every few seconds
    if (hashCount % (HASH_BATCH_SIZE * 10) === 0) {
      const elapsed = (Date.now() - startTime) / 1000;
      const hashrate = hashCount / elapsed;
      
      postMessage({
        type: 'HASHRATE_UPDATE',
        data: { 
          hashrate: Math.round(hashrate),
          totalHashes: hashCount 
        }
      });
    }
    
    // CPU usage control - add delay based on setting
    const delay = CPU_USAGE_DELAY[cpuUsage] || CPU_USAGE_DELAY[25];
    if (delay > 0) {
      await sleep(delay);
    }
  }
}

async function mineBatch() {
  for (let i = 0; i < HASH_BATCH_SIZE; i++) {
    if (!mining) break;
    
    const nonce = hashCount + i;
    const hash = await calculateHash(nonce);
    
    // Check if this is a valid solution
    // For genesis block: look for special pattern
    // For PoW blocks: check against difficulty target
    const isValidSolution = checkSolution(hash, currentJob.block_type);
    
    if (isValidSolution) {
      return {
        solution: true,
        nonce: nonce.toString(),
        hash: hash
      };
    }
  }
  
  hashCount += HASH_BATCH_SIZE;
  return { solution: false };
}

async function calculateHash(nonce) {
  // Simplified hash function for demonstration
  // In production, this would use real Argon2 WASM
  
  const input = `${currentJob.prev_hash}${currentJob.merkle_root}${currentJob.timestamp}${nonce}`;
  
  // Use crypto.subtle for actual hashing
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hashBuffer);
  const hashHex = Array.from(hashArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return hashHex;
}

function checkSolution(hash, blockType) {
  if (blockType === 'genesis') {
    // Genesis block: look for Christmas-themed pattern
    // Much easier difficulty for wallet mining
    return hash.startsWith('00') || hash.includes('c47157ma5') || hash.startsWith('wepo');
  } else {
    // Regular PoW: check against difficulty
    // Simplified difficulty for wallet mining
    return hash.startsWith('000');
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Send ready signal
postMessage({
  type: 'WORKER_READY',
  data: { message: 'Mining worker initialized' }
});