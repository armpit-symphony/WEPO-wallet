#!/usr/bin/env python3
"""
WEPO Masternode Service Manager
Implements decentralized masternode services with runtime tracking
"""

import time
import json
import threading
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

@dataclass
class MasternodeService:
    """Individual masternode service definition"""
    id: str
    name: str
    icon: str
    description: str
    resource_usage: str
    active: bool = False
    last_activity: Optional[float] = None
    activity_count: int = 0
    
@dataclass
class MasternodeStats:
    """Masternode statistics and tracking"""
    uptime_hours: float = 0
    daily_earnings: float = 0
    services_active: int = 0
    last_reward: float = 0
    total_earned: float = 0
    requirements_met: bool = False
    grace_period_remaining: int = 0
    
class MasternodeServiceManager:
    """Manages all masternode services and runtime tracking"""
    
    def __init__(self):
        self.masternodes: Dict[str, Dict] = {}
        self.services_registry: Dict[str, MasternodeService] = {}
        self.runtime_tracker: Dict[str, Dict] = {}
        self.device_requirements = {
            'computer': {
                'uptime': 9,
                'services': 3,
                'grace_period': 48,
                'max_earnings': 4.2
            },
            'mobile': {
                'uptime': 6,
                'services': 2,
                'grace_period': 24,
                'max_earnings': 2.8
            }
        }
        
        # Initialize available services
        self._initialize_services()
        
        # Start background monitoring
        self._start_monitoring()
    
    def _initialize_services(self):
        """Initialize available masternode services"""
        services = [
            MasternodeService(
                id='mixing_service',
                name='Transaction Mixing',
                icon='🔀',
                description='Anonymous transaction routing',
                resource_usage='Medium'
            ),
            MasternodeService(
                id='dex_relay',
                name='DEX Relay',
                icon='🏪',
                description='Facilitate P2P trades',
                resource_usage='High'
            ),
            MasternodeService(
                id='network_relay',
                name='Network Relay',
                icon='🌐',
                description='Forward messages/transactions',
                resource_usage='Low'
            ),
            MasternodeService(
                id='governance',
                name='Governance',
                icon='🗳️',
                description='Vote on network proposals',
                resource_usage='Low'
            ),
            MasternodeService(
                id='vault_relay',
                name='Vault Relay',
                icon='📡',
                description='Route Quantum Vault transfers',
                resource_usage='Medium'
            )
        ]
        
        for service in services:
            self.services_registry[service.id] = service
    
    def launch_masternode(self, address: str, device_type: str, selected_services: List[str]) -> Dict[str, Any]:
        """Launch a new masternode with specified services"""
        try:
            # Validate requirements
            req = self.device_requirements[device_type]
            if len(selected_services) < req['services']:
                raise ValueError(f"Need at least {req['services']} services for {device_type}")
            
            # Create masternode instance
            masternode_id = str(uuid.uuid4())
            masternode = {
                'id': masternode_id,
                'address': address,
                'device_type': device_type,
                'selected_services': selected_services,
                'active': True,
                'launch_time': time.time(),
                'last_activity': time.time(),
                'stats': MasternodeStats()
            }
            
            # Activate selected services
            for service_id in selected_services:
                if service_id in self.services_registry:
                    self.services_registry[service_id].active = True
                    self.services_registry[service_id].last_activity = time.time()
            
            # Register masternode
            self.masternodes[address] = masternode
            
            # Initialize runtime tracking
            self.runtime_tracker[address] = {
                'daily_uptime': 0,
                'session_start': time.time(),
                'last_check': time.time(),
                'penalty_points': 0,
                'grace_period_used': 0
            }
            
            print(f"✅ {device_type.title()} masternode launched for {address}")
            print(f"   Services: {', '.join(selected_services)}")
            print(f"   Requirements: {req['uptime']}h uptime, {req['services']} services")
            
            return {
                'success': True,
                'masternode_id': masternode_id,
                'device_type': device_type,
                'services_active': len(selected_services),
                'requirements': req
            }
            
        except Exception as e:
            print(f"❌ Failed to launch masternode: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def stop_masternode(self, address: str) -> Dict[str, Any]:
        """Stop a running masternode"""
        try:
            if address not in self.masternodes:
                raise ValueError("Masternode not found")
            
            masternode = self.masternodes[address]
            
            # Deactivate services
            for service_id in masternode['selected_services']:
                if service_id in self.services_registry:
                    self.services_registry[service_id].active = False
            
            # Update stats before stopping
            self._update_masternode_stats(address)
            
            # Mark as inactive
            masternode['active'] = False
            
            print(f"⏹️  Masternode stopped for {address}")
            
            return {
                'success': True,
                'message': 'Masternode stopped successfully',
                'final_stats': asdict(masternode['stats'])
            }
            
        except Exception as e:
            print(f"❌ Failed to stop masternode: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_masternode_stats(self, address: str) -> Dict[str, Any]:
        """Get current masternode statistics"""
        try:
            if address not in self.masternodes:
                return {
                    'success': False,
                    'error': 'Masternode not found'
                }
            
            masternode = self.masternodes[address]
            
            # Update stats before returning
            self._update_masternode_stats(address)
            
            return {
                'success': True,
                'masternode': {
                    'id': masternode['id'],
                    'address': address,
                    'device_type': masternode['device_type'],
                    'active': masternode['active'],
                    'services_active': len(masternode['selected_services']),
                    'stats': asdict(masternode['stats']),
                    'runtime_info': self.runtime_tracker.get(address, {})
                }
            }
            
        except Exception as e:
            print(f"❌ Failed to get stats: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _update_masternode_stats(self, address: str):
        """Update masternode statistics"""
        try:
            if address not in self.masternodes:
                return
            
            masternode = self.masternodes[address]
            runtime = self.runtime_tracker.get(address, {})
            req = self.device_requirements[masternode['device_type']]
            
            # Calculate uptime
            current_time = time.time()
            session_duration = (current_time - runtime.get('session_start', current_time)) / 3600
            daily_uptime = min(session_duration, 24)  # Cap at 24 hours
            
            # Update stats
            stats = masternode['stats']
            stats.uptime_hours = daily_uptime
            stats.services_active = len(masternode['selected_services'])
            
            # Calculate earnings based on uptime and service quality
            if daily_uptime >= req['uptime'] and stats.services_active >= req['services']:
                stats.requirements_met = True
                # Mock earnings calculation (in real implementation, this would be based on actual fees)
                hourly_rate = req['max_earnings'] / 24
                stats.daily_earnings = min(daily_uptime * hourly_rate, req['max_earnings'])
                stats.last_reward = stats.daily_earnings * 0.1  # Mock recent reward
            else:
                stats.requirements_met = False
                # Partial earnings for partial compliance
                stats.daily_earnings = (daily_uptime / req['uptime']) * req['max_earnings'] * 0.5
            
            # Update runtime tracker
            runtime['daily_uptime'] = daily_uptime
            runtime['last_check'] = current_time
            
            # Calculate grace period
            if daily_uptime < req['uptime']:
                offline_hours = max(0, req['uptime'] - daily_uptime)
                stats.grace_period_remaining = max(0, req['grace_period'] - offline_hours)
            else:
                stats.grace_period_remaining = req['grace_period']
            
        except Exception as e:
            print(f"❌ Failed to update stats: {e}")
    
    def process_service_activity(self, address: str, service_id: str, activity_data: Dict):
        """Process activity for a specific service"""
        try:
            if address not in self.masternodes:
                return False
            
            masternode = self.masternodes[address]
            
            if service_id not in masternode['selected_services']:
                return False
            
            if service_id in self.services_registry:
                service = self.services_registry[service_id]
                service.last_activity = time.time()
                service.activity_count += 1
                
                print(f"📊 Service activity: {service.name} processed activity for {address}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Failed to process service activity: {e}")
            return False
    
    def get_network_masternodes(self) -> Dict[str, Any]:
        """Get all active masternodes in the network"""
        try:
            active_masternodes = []
            
            for address, masternode in self.masternodes.items():
                if masternode['active']:
                    self._update_masternode_stats(address)
                    active_masternodes.append({
                        'address': address,
                        'device_type': masternode['device_type'],
                        'services_active': len(masternode['selected_services']),
                        'uptime_hours': masternode['stats'].uptime_hours,
                        'requirements_met': masternode['stats'].requirements_met,
                        'daily_earnings': masternode['stats'].daily_earnings
                    })
            
            return {
                'success': True,
                'total_masternodes': len(active_masternodes),
                'masternodes': active_masternodes,
                'network_stats': {
                    'total_services_active': sum(len(mn['selected_services']) for mn in self.masternodes.values() if mn['active']),
                    'average_uptime': sum(mn['stats'].uptime_hours for mn in self.masternodes.values() if mn['active']) / max(1, len(active_masternodes))
                }
            }
            
        except Exception as e:
            print(f"❌ Failed to get network masternodes: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _start_monitoring(self):
        """Start background monitoring thread"""
        def monitor_loop():
            while True:
                try:
                    # Update all active masternodes
                    for address in list(self.masternodes.keys()):
                        if self.masternodes[address]['active']:
                            self._update_masternode_stats(address)
                    
                    # Sleep for 1 minute between updates
                    time.sleep(60)
                    
                except Exception as e:
                    print(f"❌ Monitoring error: {e}")
                    time.sleep(60)
        
        # Start monitoring thread
        monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitoring_thread.start()
        print("🔄 Masternode monitoring started")

# Global instance
masternode_manager = MasternodeServiceManager()

def get_masternode_manager():
    """Get the global masternode manager instance"""
    return masternode_manager