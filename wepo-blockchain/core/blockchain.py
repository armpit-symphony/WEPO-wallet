#!/usr/bin/env python3
"""
WEPO Core Blockchain Implementation
Revolutionary cryptocurrency with hybrid PoW/PoS consensus and privacy features
"""

import hashlib
import json
import time
import struct
import socket
import threading
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import secrets
import argon2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
import os

# WEPO Network Constants
WEPO_VERSION = 70001
NETWORK_MAGIC = b'WEPO'
DEFAULT_PORT = 22567
GENESIS_TIME = 1704067200  # Jan 1, 2024
BLOCK_TIME_TARGET = 120    # 2 minutes (after year 1)
BLOCK_TIME_YEAR1 = 600     # 10 minutes (year 1)
MAX_BLOCK_SIZE = 2 * 1024 * 1024  # 2MB
COIN = 100000000  # 1 WEPO = 100,000,000 satoshis

# Consensus Parameters
POW_BLOCKS_YEAR1 = 52560      # 10-min blocks for 1 year
REWARD_Q1 = 1000 * COIN       # 1000 WEPO per block Q1 (MEGA REWARDS!)
REWARD_Q2 = 500 * COIN        # 500 WEPO per block Q2
REWARD_Q3 = 250 * COIN        # 250 WEPO per block Q3  
REWARD_Q4 = 125 * COIN        # 125 WEPO per block Q4
REWARD_YEAR2_BASE = 12.4 * COIN # 12.4 WEPO per block year 2+
HALVING_INTERVAL = 1051200    # Blocks between halvings (4 years)
POS_ACTIVATION_HEIGHT = int(POW_BLOCKS_YEAR1 * 1.5)  # 18 months
