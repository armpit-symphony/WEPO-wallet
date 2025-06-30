#!/bin/bash
# WEPO Blockchain Network Startup Script

set -e

# Configuration
DATA_DIR="./data"
LOGS_DIR="./logs"
NODE1_PORT=22567
NODE2_PORT=22568
API1_PORT=8001
API2_PORT=8002
WALLET_PORT=8003

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}🚀 WEPO Blockchain Network Launcher${NC}"
echo -e "${BLUE}========================================${NC}"

# Create directories
mkdir -p "$DATA_DIR"/{node1,node2,miner} "$LOGS_DIR"

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${RED}Port $1 is already in use${NC}"
        return 1
    fi
    return 0
}

# Function to start a process in background
start_process() {
    local name="$1"
    local command="$2"
    local logfile="$3"
    
    echo -e "${YELLOW}Starting $name...${NC}"
    eval "$command" > "$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$LOGS_DIR/$name.pid"
    echo -e "${GREEN}$name started (PID: $pid)${NC}"
    sleep 2
}

# Function to stop all processes
cleanup() {
    echo -e "\n${YELLOW}Stopping WEPO network...${NC}"
    
    for pidfile in "$LOGS_DIR"/*.pid; do
        if [ -f "$pidfile" ]; then
            local pid=$(cat "$pidfile")
            local name=$(basename "$pidfile" .pid)
            echo -e "${YELLOW}Stopping $name (PID: $pid)...${NC}"
            kill "$pid" 2>/dev/null || true
            rm -f "$pidfile"
        fi
    done
    
    echo -e "${GREEN}WEPO network stopped${NC}"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Check required ports
echo -e "${YELLOW}Checking required ports...${NC}"
if ! check_port $NODE1_PORT || ! check_port $NODE2_PORT || ! check_port $API1_PORT || ! check_port $API2_PORT || ! check_port $WALLET_PORT; then
    echo -e "${RED}Please free the required ports and try again${NC}"
    exit 1
fi

echo -e "${GREEN}All ports are available${NC}"

# Start Node 1 (Mining node)
start_process "node1" \
    "python3 core/wepo_node.py --data-dir $DATA_DIR/node1 --p2p-port $NODE1_PORT --api-port $API1_PORT" \
    "$LOGS_DIR/node1.log"

# Start Node 2 (Non-mining node for testing)
start_process "node2" \
    "python3 core/wepo_node.py --data-dir $DATA_DIR/node2 --p2p-port $NODE2_PORT --api-port $API2_PORT --no-mining" \
    "$LOGS_DIR/node2.log"

# Wait for nodes to initialize
echo -e "${YELLOW}Waiting for nodes to initialize...${NC}"
sleep 5

# Start Wallet Daemon
start_process "wallet-daemon" \
    "python3 wallet-daemon/wepo_walletd.py --node-host localhost --node-port $API1_PORT --port $WALLET_PORT" \
    "$LOGS_DIR/wallet-daemon.log"

# Wait for wallet daemon to start
sleep 3

# Start Miner
start_process "miner" \
    "python3 miner/wepo_miner.py --node http://localhost:$API1_PORT --address wepo1miner0000000000000000000000000 --threads 2" \
    "$LOGS_DIR/miner.log"

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}✅ WEPO Network Started Successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Node Information:${NC}"
echo -e "  Node 1 (Mining):     P2P: $NODE1_PORT, API: $API1_PORT"
echo -e "  Node 2 (Relay):      P2P: $NODE2_PORT, API: $API2_PORT"
echo -e "  Wallet Daemon:       API: $WALLET_PORT"
echo ""
echo -e "${BLUE}API Endpoints:${NC}"
echo -e "  Node 1 API:          http://localhost:$API1_PORT"
echo -e "  Node 2 API:          http://localhost:$API2_PORT"
echo -e "  Wallet API:          http://localhost:$WALLET_PORT"
echo ""
echo -e "${BLUE}Monitoring:${NC}"
echo -e "  Logs directory:      $LOGS_DIR/"
echo -e "  Data directory:      $DATA_DIR/"
echo ""
echo -e "${BLUE}Example API Calls:${NC}"
echo -e "  Network status:      curl http://localhost:$API1_PORT/api/network/status"
echo -e "  Latest blocks:       curl http://localhost:$API1_PORT/api/blocks/latest"
echo -e "  Mining info:         curl http://localhost:$API1_PORT/api/mining/info"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the network${NC}"

# Monitor processes
while true do
    sleep 10
    
    # Check if any process died
    for pidfile in "$LOGS_DIR"/*.pid; do
        if [ -f "$pidfile" ]; then
            local pid=$(cat "$pidfile")
            local name=$(basename "$pidfile" .pid)
            
            if ! kill -0 "$pid" 2>/dev/null; then
                echo -e "${RED}$name process died (PID: $pid)${NC}"
                echo -e "${YELLOW}Check $LOGS_DIR/$name.log for details${NC}"
                cleanup
            fi
        fi
    done
done