# WEPO Desktop Wallet - Development Guide

## Quick Start for Users

### Windows (Recommended)
1. Download the latest release ZIP from GitHub
2. Extract to any folder (e.g., `C:\WEPO-Wallet\`)
3. Double-click `start-wallet.bat`
4. The wallet will automatically install dependencies and launch

### Requirements
- Windows 10/11 (64-bit)
- Internet connection (for Node.js package installation)
- 500MB free disk space

## Development Setup

### Prerequisites
- Node.js 18+ (https://nodejs.org/)
- Git (https://git-scm.com/)

### Installation
```bash
# Clone the repository
git clone https://github.com/wepo-project/wepo-desktop-wallet.git
cd wepo-desktop-wallet

# Install dependencies
npm install

# Install frontend dependencies
cd src/frontend
npm install
cd ../..

# Start development mode
npm run dev
```

### Build for Distribution
```bash
# Build frontend
npm run build

# Create Windows distribution
npm run dist-win

# Output will be in dist/ folder
```

## Project Structure

```
wepo-desktop-wallet/
├── src/
│   ├── main.js              # Electron main process
│   ├── preload.js           # Secure IPC bridge
│   ├── backend/
│   │   └── server.js        # Node.js API server
│   └── frontend/            # React application
│       ├── src/
│       │   ├── components/  # UI components
│       │   ├── contexts/    # React contexts
│       │   └── utils/       # Utility functions
│       └── build/           # Built frontend (after npm run build)
├── assets/
│   ├── icon.png            # Application icon
│   └── icon.ico            # Windows icon
├── scripts/
│   └── build-desktop.js    # Build automation
├── start-wallet.bat        # Windows launcher
├── package.json            # Main package configuration
└── README.md              # User documentation
```

## Features Implemented

### ✅ Core Wallet Features
- **Wallet Creation**: BIP-39 compliant seed phrase generation
- **Wallet Recovery**: Import from 12-word seed phrase
- **WEPO Transactions**: Send and receive WEPO tokens
- **Balance Display**: Real-time balance checking

### ✅ Bitcoin Integration
- **Self-Custodial Bitcoin**: BIP-44 standard derivation
- **Bitcoin Addresses**: P2PKH (Legacy) format for maximum compatibility
- **Recovery Information**: Clear instructions for wallet portability
- **Mainnet Ready**: Real Bitcoin network integration

### ✅ Privacy Features
- **Quantum Vault**: Ultimate privacy protection with zk-STARK
- **Ghost Transfers**: Anonymous transaction capability
- **Privacy Modes**: Public and Private transaction options

### ✅ Network Participation
- **Desktop Mining**: Optimized mining for desktop computers
- **Staking**: Earn rewards through Proof-of-Stake
- **Masternodes**: Run masternode services (10,000 WEPO collateral)

### ✅ Security
- **Local Storage**: Private keys never leave the device
- **Secure IPC**: Contextual isolation between processes
- **Menu Integration**: Native OS menu integration
- **Auto-updates**: Planned for future releases

## API Endpoints

The desktop wallet includes a local Node.js API server that provides:

### Wallet Management
- `POST /api/wallet/create` - Create new wallet
- `GET /api/wallet/:address` - Get wallet information

### Bitcoin Integration
- `GET /api/bitcoin/balance/:address` - Check Bitcoin balance
- `GET /api/bitcoin/network/status` - Bitcoin network status
- `POST /api/bitcoin/wallet/init` - Initialize Bitcoin wallet

### Privacy Features
- `POST /api/vault/create` - Create Quantum Vault
- `GET /api/vault/wallet/:address` - Get vault information

### Network Services
- `POST /api/mining/start` - Start desktop mining
- `GET /api/mining/status` - Get mining status
- `POST /api/staking/stake` - Activate staking
- `POST /api/masternode/setup` - Setup masternode

## Security Considerations

### ✅ Implemented
- **No Remote Code Execution**: All code is bundled and verified
- **Local API Only**: Backend only accepts localhost connections
- **Secure Storage**: Encrypted wallet data using OS keychain
- **Process Isolation**: Renderer and main processes are isolated

### 🔄 Future Security Enhancements
- **Code Signing**: Digital signature verification
- **Auto-Updates**: Secure automatic updates
- **Hardware Wallet**: Integration with hardware devices
- **Multi-Signature**: Enhanced security for large amounts

## Deployment

### Creating GitHub Release

1. **Build the application**:
   ```bash
   npm run build
   npm run dist-win
   ```

2. **Create release package**:
   ```bash
   # The dist/ folder will contain:
   # - wepo-desktop-wallet-win-x64.zip (Portable)
   # - WEPO Wallet Setup.exe (Installer)
   ```

3. **Upload to GitHub**:
   - Create new release on GitHub
   - Upload the ZIP file for easy download
   - Include installation instructions

### User Installation
Users simply need to:
1. Download `wepo-desktop-wallet-win-x64.zip`
2. Extract to desired location
3. Run `start-wallet.bat`

## Troubleshooting

### Common Issues

**"Node.js not found"**
- Install Node.js from https://nodejs.org/
- Restart command prompt/terminal

**"Failed to install dependencies"**
- Check internet connection
- Try running as administrator
- Clear npm cache: `npm cache clean --force`

**"Wallet won't start"**
- Check if port 8001 is available
- Disable antivirus temporarily
- Run from a folder without spaces in the path

### Debug Mode
```bash
# Enable debug logging
set DEBUG=wepo:*
npm start
```

## Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

## License

MIT License - see LICENSE file for details.

## Christmas Day 2025 🎄

This desktop wallet is ready for the WEPO Genesis Block launch on Christmas Day 2025!