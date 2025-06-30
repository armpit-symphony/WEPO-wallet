#!/usr/bin/env python3
"""
WEPO P2P Network Implementation
Peer-to-peer networking for revolutionary cryptocurrency
"""

import socket
import threading
import time
import json
import struct
import hashlib
from typing import List, Dict, Optional, Set, Callable
from dataclasses import dataclass, asdict
from enum import IntEnum
import random
import select

# Network Constants
NETWORK_MAGIC = b'WEPO'
PROTOCOL_VERSION = 70001
DEFAULT_PORT = 22567
MAX_PEERS = 8
CONNECTION_TIMEOUT = 30
PING_INTERVAL = 60
MAX_MESSAGE_SIZE = 32 * 1024 * 1024  # 32MB

class MessageType(IntEnum):
    """P2P Message types"""
    VERSION = 0x01
    VERACK = 0x02
    PING = 0x03
    PONG = 0x04
    GETADDR = 0x05
    ADDR = 0x06
    INV = 0x07
    GETDATA = 0x08
    BLOCK = 0x09
    TX = 0x0A
    GETBLOCKS = 0x0B
    GETHEADERS = 0x0C
    HEADERS = 0x0D
    MEMPOOL = 0x0E
    REJECT = 0x0F
    
    # WEPO-specific messages
    MASTERNODE = 0x10
    STAKE = 0x11
    PRIVACY = 0x12
    DEXORDER = 0x13
    ATOMICSWAP = 0x14

class InventoryType(IntEnum):
    """Inventory object types"""
    ERROR = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3
    MSG_CMPCT_BLOCK = 4

@dataclass
class NetworkAddress:
    """Network address structure"""
    time: int
    services: int
    ip: str
    port: int

@dataclass
class InventoryVector:
    """Inventory vector for announcing objects"""
    type: int
    hash: str

@dataclass
class P2PMessage:
    """P2P network message"""
    magic: bytes
    command: str
    length: int
    checksum: bytes
    payload: bytes

class WepoP2PNode:
    """WEPO P2P Network Node"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT, 
                 user_agent: str = "/WepoCore:1.0.0/"):
        self.host = host
        self.port = port
        self.user_agent = user_agent
        self.node_id = hashlib.sha256(f"{host}:{port}:{time.time()}".encode()).hexdigest()[:16]
        
        # Network state
        self.peers: Dict[str, 'WepoPeer'] = {}
        self.known_addresses: Set[tuple] = set()
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        
        # Message handlers
        self.message_handlers: Dict[str, Callable] = {
            'version': self.handle_version,
            'verack': self.handle_verack,
            'ping': self.handle_ping,
            'pong': self.handle_pong,
            'getaddr': self.handle_getaddr,
            'addr': self.handle_addr,
            'inv': self.handle_inv,
            'getdata': self.handle_getdata,
            'block': self.handle_block,
            'tx': self.handle_tx,
            'getblocks': self.handle_getblocks,
            'getheaders': self.handle_getheaders,
        }
        
        # Callbacks for blockchain integration
        self.on_new_block: Optional[Callable] = None
        self.on_new_transaction: Optional[Callable] = None
        self.get_block_callback: Optional[Callable] = None
        self.get_headers_callback: Optional[Callable] = None
        
        # DNS seeds for peer discovery
        self.dns_seeds = [
            "seed1.wepo.network",
            "seed2.wepo.network", 
            "seed3.wepo.network"
        ]
        
        print(f"WEPO P2P Node initialized: {self.node_id}")
        print(f"Listening on: {host}:{port}")
    
    def create_message(self, command: str, payload: bytes = b'') -> bytes:
        """Create a P2P protocol message"""
        # Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        # Create header
        header = struct.pack('<4s12sI4s', 
                           NETWORK_MAGIC,
                           command.encode().ljust(12, b'\x00'),
                           len(payload),
                           checksum)
        
        return header + payload
    
    def parse_message(self, data: bytes) -> Optional[P2PMessage]:
        """Parse incoming P2P message"""
        if len(data) < 24:  # Header size
            return None
        
        try:
            # Parse header
            magic, command_bytes, length, checksum = struct.unpack('<4s12sI4s', data[:24])
            
            if magic != NETWORK_MAGIC:
                print(f"Invalid magic bytes: {magic}")
                return None
            
            command = command_bytes.rstrip(b'\x00').decode()
            
            if len(data) < 24 + length:
                print(f"Incomplete message: expected {24 + length}, got {len(data)}")
                return None
            
            payload = data[24:24 + length]
            
            # Verify checksum
            expected_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            if checksum != expected_checksum:
                print(f"Invalid checksum for {command}")
                return None
            
            return P2PMessage(magic, command, length, checksum, payload)
            
        except Exception as e:
            print(f"Error parsing message: {e}")
            return None
    
    def create_version_message(self) -> bytes:
        """Create version message"""
        payload_data = {
            'version': PROTOCOL_VERSION,
            'services': 1,  # NODE_NETWORK
            'timestamp': int(time.time()),
            'addr_recv': {'ip': '127.0.0.1', 'port': self.port},
            'addr_from': {'ip': self.host, 'port': self.port},
            'nonce': random.randint(0, 2**64 - 1),
            'user_agent': self.user_agent,
            'start_height': 0,  # TODO: Get from blockchain
            'relay': True
        }
        
        payload = json.dumps(payload_data).encode()
        return self.create_message('version', payload)
    
    def start_server(self):
        """Start P2P server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_PEERS)
            self.running = True
            
            print(f"P2P server started on {self.host}:{self.port}")
            
            # Start accepting connections
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
            # Start periodic tasks
            threading.Thread(target=self.periodic_tasks, daemon=True).start()
            
        except Exception as e:
            print(f"Failed to start P2P server: {e}")
            self.running = False
    
    def stop_server(self):
        """Stop P2P server"""
        print("Stopping P2P server...")
        self.running = False
        
        # Close all peer connections
        for peer in list(self.peers.values()):
            peer.disconnect()
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
        
        print("P2P server stopped")
    
    def accept_connections(self):
        """Accept incoming peer connections"""
        while self.running:
            try:
                if self.server_socket:
                    # Use select for non-blocking accept
                    ready, _, _ = select.select([self.server_socket], [], [], 1.0)
                    if ready:
                        conn, addr = self.server_socket.accept()
                        if len(self.peers) < MAX_PEERS:
                            peer = WepoPeer(conn, addr, self, incoming=True)
                            peer.start()
                        else:
                            conn.close()
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
                break
    
    def connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer"""
        if len(self.peers) >= MAX_PEERS:
            return False
        
        peer_id = f"{host}:{port}"
        if peer_id in self.peers:
            return False
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(CONNECTION_TIMEOUT)
            sock.connect((host, port))
            
            peer = WepoPeer(sock, (host, port), self, incoming=False)
            peer.start()
            return True
            
        except Exception as e:
            print(f"Failed to connect to {host}:{port}: {e}")
            return False
    
    def discover_peers(self):
        """Discover peers through DNS seeds and existing connections"""
        print("Discovering peers...")
        
        # Try DNS seeds (simplified - would use actual DNS resolution)
        seed_addresses = [
            ("127.0.0.1", 22567),  # Local node for testing
            ("127.0.0.1", 22568),  # Another local node
        ]
        
        for host, port in seed_addresses:
            if len(self.peers) < MAX_PEERS:
                self.connect_to_peer(host, port)
        
        # Request addresses from existing peers
        for peer in self.peers.values():
            if peer.is_connected():
                peer.send_getaddr()
    
    def periodic_tasks(self):
        """Periodic maintenance tasks"""
        while self.running:
            try:
                # Clean up disconnected peers
                disconnected = [peer_id for peer_id, peer in self.peers.items() 
                              if not peer.is_connected()]
                for peer_id in disconnected:
                    del self.peers[peer_id]
                
                # Send pings to peers
                for peer in self.peers.values():
                    if peer.is_connected():
                        peer.send_ping()
                
                # Try to maintain connections
                if len(self.peers) < MAX_PEERS // 2:
                    self.discover_peers()
                
                time.sleep(PING_INTERVAL)
                
            except Exception as e:
                print(f"Error in periodic tasks: {e}")
    
    def broadcast_to_peers(self, message: bytes):
        """Broadcast message to all connected peers"""
        for peer in self.peers.values():
            if peer.is_connected():
                peer.send_raw(message)
    
    def broadcast_transaction(self, tx_data: dict):
        """Broadcast transaction to network"""
        inv_msg = self.create_inv_message([{
            'type': InventoryType.MSG_TX,
            'hash': tx_data.get('txid', '')
        }])
        self.broadcast_to_peers(inv_msg)
    
    def broadcast_block(self, block_data: dict):
        """Broadcast block to network"""
        inv_msg = self.create_inv_message([{
            'type': InventoryType.MSG_BLOCK,
            'hash': block_data.get('hash', '')
        }])
        self.broadcast_to_peers(inv_msg)
    
    def create_inv_message(self, inventory: List[dict]) -> bytes:
        """Create inventory message"""
        payload_data = {
            'count': len(inventory),
            'inventory': inventory
        }
        payload = json.dumps(payload_data).encode()
        return self.create_message('inv', payload)
    
    # Message handlers
    def handle_version(self, peer: 'WepoPeer', payload: bytes):
        """Handle version message"""
        try:
            data = json.loads(payload.decode())
            peer.version = data.get('version', 0)
            peer.services = data.get('services', 0)
            peer.user_agent = data.get('user_agent', '')
            peer.start_height = data.get('start_height', 0)
            
            print(f"Received version from {peer.peer_id}: {peer.user_agent}")
            
            # Send verack
            peer.send_verack()
            
        except Exception as e:
            print(f"Error handling version: {e}")
    
    def handle_verack(self, peer: 'WepoPeer', payload: bytes):
        """Handle version acknowledgment"""
        peer.handshake_complete = True
        print(f"Handshake complete with {peer.peer_id}")
    
    def handle_ping(self, peer: 'WepoPeer', payload: bytes):
        """Handle ping message"""
        try:
            data = json.loads(payload.decode()) if payload else {}
            nonce = data.get('nonce', 0)
            peer.send_pong(nonce)
        except Exception as e:
            print(f"Error handling ping: {e}")
    
    def handle_pong(self, peer: 'WepoPeer', payload: bytes):
        """Handle pong message"""
        peer.last_pong = time.time()
    
    def handle_getaddr(self, peer: 'WepoPeer', payload: bytes):
        """Handle address request"""
        # Send known addresses
        addresses = list(self.known_addresses)[:1000]  # Limit to 1000
        addr_msg = self.create_addr_message(addresses)
        peer.send_raw(addr_msg)
    
    def handle_addr(self, peer: 'WepoPeer', payload: bytes):
        """Handle address message"""
        try:
            data = json.loads(payload.decode())
            addresses = data.get('addresses', [])
            
            for addr in addresses:
                host = addr.get('ip', '')
                port = addr.get('port', 0)
                if host and port:
                    self.known_addresses.add((host, port))
            
            print(f"Received {len(addresses)} addresses from {peer.peer_id}")
            
        except Exception as e:
            print(f"Error handling addr: {e}")
    
    def handle_inv(self, peer: 'WepoPeer', payload: bytes):
        """Handle inventory message"""
        try:
            data = json.loads(payload.decode())
            inventory = data.get('inventory', [])
            
            # Request data for items we don't have
            getdata_items = []
            for item in inventory:
                item_type = item.get('type')
                item_hash = item.get('hash')
                
                if item_type == InventoryType.MSG_BLOCK:
                    # Check if we have this block
                    getdata_items.append(item)
                elif item_type == InventoryType.MSG_TX:
                    # Check if we have this transaction
                    getdata_items.append(item)
            
            if getdata_items:
                getdata_msg = self.create_getdata_message(getdata_items)
                peer.send_raw(getdata_msg)
                
        except Exception as e:
            print(f"Error handling inv: {e}")
    
    def handle_getdata(self, peer: 'WepoPeer', payload: bytes):
        """Handle getdata message"""
        try:
            data = json.loads(payload.decode())
            inventory = data.get('inventory', [])
            
            for item in inventory:
                item_type = item.get('type')
                item_hash = item.get('hash')
                
                if item_type == InventoryType.MSG_BLOCK and self.get_block_callback:
                    block_data = self.get_block_callback(item_hash)
                    if block_data:
                        block_msg = self.create_block_message(block_data)
                        peer.send_raw(block_msg)
                        
                elif item_type == InventoryType.MSG_TX:
                    # TODO: Get transaction data
                    pass
                    
        except Exception as e:
            print(f"Error handling getdata: {e}")
    
    def handle_block(self, peer: 'WepoPeer', payload: bytes):
        """Handle block message"""
        try:
            data = json.loads(payload.decode())
            print(f"Received block from {peer.peer_id}: {data.get('hash', 'unknown')}")
            
            if self.on_new_block:
                self.on_new_block(data)
                
        except Exception as e:
            print(f"Error handling block: {e}")
    
    def handle_tx(self, peer: 'WepoPeer', payload: bytes):
        """Handle transaction message"""
        try:
            data = json.loads(payload.decode())
            print(f"Received transaction from {peer.peer_id}: {data.get('txid', 'unknown')}")
            
            if self.on_new_transaction:
                self.on_new_transaction(data)
                
        except Exception as e:
            print(f"Error handling tx: {e}")
    
    def handle_getblocks(self, peer: 'WepoPeer', payload: bytes):
        """Handle getblocks message"""
        # TODO: Implement block locator response
        pass
    
    def handle_getheaders(self, peer: 'WepoPeer', payload: bytes):
        """Handle getheaders message"""
        # TODO: Implement headers response
        pass
    
    def create_addr_message(self, addresses: List[tuple]) -> bytes:
        """Create address message"""
        addr_list = []
        for host, port in addresses:
            addr_list.append({
                'time': int(time.time()),
                'services': 1,
                'ip': host,
                'port': port
            })
        
        payload_data = {
            'count': len(addr_list),
            'addresses': addr_list
        }
        payload = json.dumps(payload_data).encode()
        return self.create_message('addr', payload)
    
    def create_getdata_message(self, inventory: List[dict]) -> bytes:
        """Create getdata message"""
        payload_data = {
            'count': len(inventory),
            'inventory': inventory
        }
        payload = json.dumps(payload_data).encode()
        return self.create_message('getdata', payload)
    
    def create_block_message(self, block_data: dict) -> bytes:
        """Create block message"""
        payload = json.dumps(block_data).encode()
        return self.create_message('block', payload)
    
    def get_network_info(self) -> dict:
        """Get network information"""
        return {
            'node_id': self.node_id,
            'version': PROTOCOL_VERSION,
            'peer_count': len(self.peers),
            'connected_peers': [peer.peer_id for peer in self.peers.values() if peer.is_connected()],
            'known_addresses': len(self.known_addresses),
            'port': self.port
        }

class WepoPeer:
    """Individual peer connection"""
    
    def __init__(self, socket: socket.socket, address: tuple, node: WepoP2PNode, incoming: bool = False):
        self.socket = socket
        self.address = address
        self.node = node
        self.incoming = incoming
        self.peer_id = f"{address[0]}:{address[1]}"
        
        # Peer state
        self.connected = True
        self.handshake_complete = False
        self.version = 0
        self.services = 0
        self.user_agent = ""
        self.start_height = 0
        self.last_ping = time.time()
        self.last_pong = time.time()
        
        # Message buffer
        self.receive_buffer = b''
        
        print(f"New peer connection: {self.peer_id} ({'incoming' if incoming else 'outgoing'})")
    
    def start(self):
        """Start peer communication"""
        # Add to node's peer list
        self.node.peers[self.peer_id] = self
        
        # Start receive thread
        threading.Thread(target=self.receive_loop, daemon=True).start()
        
        # Send version message if outgoing connection
        if not self.incoming:
            self.send_version()
    
    def send_raw(self, data: bytes):
        """Send raw data to peer"""
        try:
            if self.connected:
                self.socket.send(data)
        except Exception as e:
            print(f"Error sending to {self.peer_id}: {e}")
            self.disconnect()
    
    def send_version(self):
        """Send version message"""
        version_msg = self.node.create_version_message()
        self.send_raw(version_msg)
    
    def send_verack(self):
        """Send version acknowledgment"""
        verack_msg = self.node.create_message('verack')
        self.send_raw(verack_msg)
    
    def send_ping(self):
        """Send ping message"""
        nonce = random.randint(0, 2**32 - 1)
        payload_data = {'nonce': nonce}
        payload = json.dumps(payload_data).encode()
        ping_msg = self.node.create_message('ping', payload)
        self.send_raw(ping_msg)
        self.last_ping = time.time()
    
    def send_pong(self, nonce: int):
        """Send pong message"""
        payload_data = {'nonce': nonce}
        payload = json.dumps(payload_data).encode()
        pong_msg = self.node.create_message('pong', payload)
        self.send_raw(pong_msg)
    
    def send_getaddr(self):
        """Send getaddr message"""
        getaddr_msg = self.node.create_message('getaddr')
        self.send_raw(getaddr_msg)
    
    def receive_loop(self):
        """Main receive loop"""
        while self.connected:
            try:
                # Set socket timeout
                self.socket.settimeout(1.0)
                data = self.socket.recv(4096)
                
                if not data:
                    break
                
                self.receive_buffer += data
                
                # Process complete messages
                self.process_messages()
                
            except socket.timeout:
                # Check for ping timeout
                if time.time() - self.last_pong > CONNECTION_TIMEOUT * 2:
                    print(f"Ping timeout for {self.peer_id}")
                    break
                continue
            except Exception as e:
                print(f"Receive error from {self.peer_id}: {e}")
                break
        
        self.disconnect()
    
    def process_messages(self):
        """Process messages from receive buffer"""
        while len(self.receive_buffer) >= 24:  # Minimum header size
            # Try to parse message
            message = self.node.parse_message(self.receive_buffer)
            if not message:
                break
            
            # Remove processed data from buffer
            message_size = 24 + message.length
            self.receive_buffer = self.receive_buffer[message_size:]
            
            # Handle message
            handler = self.node.message_handlers.get(message.command)
            if handler:
                try:
                    handler(self, message.payload)
                except Exception as e:
                    print(f"Error handling {message.command} from {self.peer_id}: {e}")
            else:
                print(f"Unknown message type: {message.command}")
    
    def is_connected(self) -> bool:
        """Check if peer is connected"""
        return self.connected and self.handshake_complete
    
    def disconnect(self):
        """Disconnect from peer"""
        if self.connected:
            print(f"Disconnecting from {self.peer_id}")
            self.connected = False
            try:
                self.socket.close()
            except:
                pass

def main():
    """Test the P2P network"""
    print("=== WEPO P2P Network Test ===")
    
    # Create P2P node
    node = WepoP2PNode()
    
    try:
        # Start server
        node.start_server()
        
        # Wait for connections
        print("P2P node running... Press Ctrl+C to stop")
        while True:
            time.sleep(1)
            
            # Print network info every 30 seconds
            if int(time.time()) % 30 == 0:
                info = node.get_network_info()
                print(f"\nNetwork Info: {info}")
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        node.stop_server()

if __name__ == "__main__":
    main()