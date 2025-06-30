#!/usr/bin/env python3
"""
WEPO Miner - Argon2 Proof of Work Mining Software
Revolutionary cryptocurrency mining with memory-hard algorithm
"""

import argparse
import time
import json
import threading
import queue
import hashlib
import struct
from typing import Optional, Dict, Any
import requests
import argon2
from dataclasses import dataclass
import signal
import sys

# Mining Constants
DEFAULT_THREADS = 1
DEFAULT_INTENSITY = 4096  # Memory cost in KB
DEFAULT_ITERATIONS = 3
HASH_UPDATE_INTERVAL = 1000
STATS_UPDATE_INTERVAL = 30

@dataclass
class MiningJob:
    """Mining job received from pool or solo mining"""
    job_id: str
    prev_hash: str
    merkle_root: str
    timestamp: int
    bits: int
    height: int
    target_difficulty: int
    miner_address: str

@dataclass
class MiningStats:
    """Mining statistics"""
    start_time: float
    total_hashes: int
    blocks_found: int
    current_hashrate: float
    average_hashrate: float
    best_difficulty: int
    last_update: float

class WepoArgon2Miner:
    """Argon2 PoW Miner for WEPO"""
    
    def __init__(self, threads: int = DEFAULT_THREADS, intensity: int = DEFAULT_INTENSITY):
        self.threads = threads
        self.intensity = intensity
        self.hasher = argon2.PasswordHasher(
            time_cost=DEFAULT_ITERATIONS,
            memory_cost=intensity,
            parallelism=1,
            hash_len=32,
            salt_len=16
        )
        
        self.mining = False
        self.current_job: Optional[MiningJob] = None
        self.stats = MiningStats(
            start_time=time.time(),
            total_hashes=0,
            blocks_found=0,
            current_hashrate=0.0,
            average_hashrate=0.0,
            best_difficulty=0,
            last_update=time.time()
        )
        
        # Thread management
        self.mining_threads = []
        self.work_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
        
        # Statistics lock
        self.stats_lock = threading.Lock()
        
        print(f"WEPO Miner initialized:")
        print(f"  Threads: {self.threads}")
        print(f"  Memory cost: {self.intensity} KB")
        print(f"  Time cost: {DEFAULT_ITERATIONS}")
    
    def calculate_difficulty(self, block_hash: str) -> int:
        """Calculate difficulty (leading zeros) of a hash"""
        leading_zeros = 0
        for char in block_hash:
            if char == '0':
                leading_zeros += 1
            else:
                break
        return leading_zeros
    
    def check_target(self, block_hash: str, target_difficulty: int) -> bool:
        """Check if hash meets target difficulty"""
        return self.calculate_difficulty(block_hash) >= target_difficulty
    
    def mine_work(self, worker_id: int, job: MiningJob, start_nonce: int, nonce_range: int):
        """Mining worker function"""
        print(f"Worker {worker_id} starting: nonce range {start_nonce} - {start_nonce + nonce_range}")
        
        local_hashes = 0
        last_stats_update = time.time()
        
        for nonce_offset in range(nonce_range):
            if self.stop_event.is_set():
                break
            
            nonce = start_nonce + nonce_offset
            local_hashes += 1
            
            # Create header data for hashing
            header_data = f"{job.prev_hash}{job.merkle_root}{job.timestamp}{job.bits}{nonce}"
            
            try:
                # Argon2 hash
                hash_result = self.hasher.hash(header_data)
                block_hash = hashlib.sha256(hash_result.encode()).hexdigest()
                
                # Check if we found a valid hash
                difficulty = self.calculate_difficulty(block_hash)
                
                # Update best difficulty found
                with self.stats_lock:
                    if difficulty > self.stats.best_difficulty:
                        self.stats.best_difficulty = difficulty
                
                # Check if hash meets target
                if self.check_target(block_hash, job.target_difficulty):
                    print(f"\n🎉 BLOCK FOUND! Worker {worker_id}")
                    print(f"   Hash: {block_hash}")
                    print(f"   Nonce: {nonce}")
                    print(f"   Difficulty: {difficulty}")
                    
                    # Put result in queue
                    result = {
                        'job_id': job.job_id,
                        'nonce': nonce,
                        'hash': block_hash,
                        'difficulty': difficulty,
                        'worker_id': worker_id
                    }
                    self.result_queue.put(result)
                    
                    with self.stats_lock:
                        self.stats.blocks_found += 1
                    
                    return True
                
                # Update statistics periodically
                if local_hashes % HASH_UPDATE_INTERVAL == 0:
                    current_time = time.time()
                    if current_time - last_stats_update >= 1.0:
                        with self.stats_lock:
                            self.stats.total_hashes += local_hashes
                            
                            # Calculate hashrate
                            elapsed = current_time - last_stats_update
                            worker_hashrate = local_hashes / elapsed
                            
                            print(f"Worker {worker_id}: {worker_hashrate:.2f} H/s, "
                                  f"Nonce: {nonce}, Best: {self.stats.best_difficulty}")
                        
                        local_hashes = 0
                        last_stats_update = current_time
                
            except Exception as e:
                # Argon2 error, continue
                continue
        
        # Final stats update
        with self.stats_lock:
            self.stats.total_hashes += local_hashes
        
        print(f"Worker {worker_id} finished")
        return False
    
    def start_mining_threads(self, job: MiningJob):
        """Start mining threads for a job"""
        self.stop_event.clear()
        self.current_job = job
        
        # Calculate nonce range per thread
        max_nonce = 2**32
        nonces_per_thread = max_nonce // self.threads
        
        print(f"\nStarting {self.threads} mining threads for job {job.job_id}")
        print(f"Target difficulty: {job.target_difficulty}")
        print(f"Nonces per thread: {nonces_per_thread:,}")
        
        # Start worker threads
        for i in range(self.threads):
            start_nonce = i * nonces_per_thread
            thread = threading.Thread(
                target=self.mine_work,
                args=(i, job, start_nonce, nonces_per_thread),
                daemon=True
            )
            thread.start()
            self.mining_threads.append(thread)
    
    def stop_mining(self):
        """Stop all mining threads"""
        print("\nStopping mining...")
        self.stop_event.set()
        self.mining = False
        
        # Wait for threads to finish
        for thread in self.mining_threads:
            thread.join(timeout=5.0)
        
        self.mining_threads.clear()
        print("Mining stopped")
    
    def print_stats(self):
        """Print mining statistics"""
        with self.stats_lock:
            current_time = time.time()
            total_elapsed = current_time - self.stats.start_time
            
            if total_elapsed > 0:
                avg_hashrate = self.stats.total_hashes / total_elapsed
            else:
                avg_hashrate = 0
            
            print(f"\n--- Mining Statistics ---")
            print(f"Runtime: {total_elapsed:.0f} seconds")
            print(f"Total hashes: {self.stats.total_hashes:,}")
            print(f"Blocks found: {self.stats.blocks_found}")
            print(f"Average hashrate: {avg_hashrate:.2f} H/s")
            print(f"Best difficulty: {self.stats.best_difficulty}")
            
            if self.current_job:
                print(f"Current job: {self.current_job.job_id}")
                print(f"Target difficulty: {self.current_job.target_difficulty}")

class WepoSoloMiner:
    """Solo mining client for WEPO"""
    
    def __init__(self, node_url: str, miner_address: str, threads: int = DEFAULT_THREADS):
        self.node_url = node_url.rstrip('/')
        self.miner_address = miner_address
        self.miner = WepoArgon2Miner(threads)
        self.running = False
        
        print(f"Solo miner initialized:")
        print(f"  Node URL: {self.node_url}")
        print(f"  Miner address: {self.miner_address}")
    
    def get_mining_job(self) -> Optional[MiningJob]:
        """Get mining job from node"""
        try:
            response = requests.get(f"{self.node_url}/api/mining/getwork", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return MiningJob(
                    job_id=data['job_id'],
                    prev_hash=data['prev_hash'],
                    merkle_root=data['merkle_root'],
                    timestamp=data['timestamp'],
                    bits=data['bits'],
                    height=data['height'],
                    target_difficulty=data['target_difficulty'],
                    miner_address=self.miner_address
                )
        except Exception as e:
            print(f"Error getting mining job: {e}")
        
        return None
    
    def submit_solution(self, result: dict) -> bool:
        """Submit mining solution to node"""
        try:
            submit_data = {
                'job_id': result['job_id'],
                'nonce': result['nonce'],
                'miner_address': self.miner_address
            }
            
            response = requests.post(
                f"{self.node_url}/api/mining/submit",
                json=submit_data,
                timeout=10
            )
            
            if response.status_code == 200:
                result_data = response.json()
                if result_data.get('accepted', False):
                    print(f"✅ Solution accepted! Block {result_data.get('height', '?')}")
                    return True
                else:
                    print(f"❌ Solution rejected: {result_data.get('reason', 'Unknown')}")
            else:
                print(f"❌ Submit failed: HTTP {response.status_code}")
        
        except Exception as e:
            print(f"Error submitting solution: {e}")
        
        return False
    
    def start_solo_mining(self):
        """Start solo mining"""
        print("\n🚀 Starting WEPO solo mining...")
        self.running = True
        
        # Statistics thread
        stats_thread = threading.Thread(target=self.stats_worker, daemon=True)
        stats_thread.start()
        
        while self.running:
            try:
                # Get new mining job
                job = self.get_mining_job()
                if not job:
                    print("No mining job available, retrying in 10 seconds...")
                    time.sleep(10)
                    continue
                
                print(f"\nNew mining job received:")
                print(f"  Job ID: {job.job_id}")
                print(f"  Height: {job.height}")
                print(f"  Target difficulty: {job.target_difficulty}")
                
                # Start mining
                self.miner.start_mining_threads(job)
                
                # Wait for result or new job
                solution_found = False
                job_start_time = time.time()
                
                while self.running and not solution_found:
                    try:
                        # Check for solution
                        result = self.miner.result_queue.get(timeout=1.0)
                        solution_found = True
                        
                        # Submit solution
                        if self.submit_solution(result):
                            print(f"Block successfully mined and submitted!")
                        
                        # Stop current mining
                        self.miner.stop_mining()
                        
                    except queue.Empty:
                        # Check if we should get a new job (every 30 seconds)
                        if time.time() - job_start_time > 30:
                            print("Getting new mining job...")
                            self.miner.stop_mining()
                            break
                        continue
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Mining error: {e}")
                time.sleep(5)
        
        self.miner.stop_mining()
        print("Solo mining stopped")
    
    def stats_worker(self):
        """Statistics update worker"""
        while self.running:
            time.sleep(STATS_UPDATE_INTERVAL)
            if self.running:
                self.miner.print_stats()
    
    def stop(self):
        """Stop mining"""
        self.running = False
        self.miner.stop_mining()

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nReceived shutdown signal...")
    global miner
    if 'miner' in globals():
        miner.stop()
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='WEPO Cryptocurrency Miner')
    parser.add_argument('--node', default='http://localhost:8001', 
                       help='WEPO node URL (default: http://localhost:8001)')
    parser.add_argument('--address', required=True,
                       help='Miner address for rewards')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS,
                       help=f'Number of mining threads (default: {DEFAULT_THREADS})')
    parser.add_argument('--intensity', type=int, default=DEFAULT_INTENSITY,
                       help=f'Argon2 memory cost in KB (default: {DEFAULT_INTENSITY})')
    parser.add_argument('--test', action='store_true',
                       help='Run mining test without connecting to node')
    
    args = parser.parse_args()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("=" * 50)
    print("🚀 WEPO Miner - Revolutionary Cryptocurrency")
    print("=" * 50)
    print(f"Version: 1.0.0")
    print(f"Algorithm: Argon2 (Memory-hard PoW)")
    print(f"Threads: {args.threads}")
    print(f"Memory intensity: {args.intensity} KB")
    print("=" * 50)
    
    if args.test:
        # Test mining without node connection
        print("\n🧪 Running mining test...")
        test_miner = WepoArgon2Miner(args.threads, args.intensity)
        
        # Create test job
        test_job = MiningJob(
            job_id="test_job",
            prev_hash="0" * 64,
            merkle_root="a" * 64,
            timestamp=int(time.time()),
            bits=0x1d00ffff,
            height=1,
            target_difficulty=2,  # Easy target for testing
            miner_address=args.address
        )
        
        print("Starting test mining for 30 seconds...")
        test_miner.start_mining_threads(test_job)
        
        time.sleep(30)
        test_miner.stop_mining()
        test_miner.print_stats()
        
    else:
        # Solo mining
        global miner
        miner = WepoSoloMiner(args.node, args.address, args.threads)
        miner.start_solo_mining()

if __name__ == "__main__":
    main()