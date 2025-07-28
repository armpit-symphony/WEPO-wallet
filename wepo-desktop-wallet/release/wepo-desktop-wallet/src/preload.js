const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // App info
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  getAppPath: () => ipcRenderer.invoke('get-app-path'),
  
  // Menu actions
  onMenuAction: (callback) => {
    ipcRenderer.on('menu-action', callback);
  },
  
  // Wallet operations
  openWallet: () => ipcRenderer.invoke('open-wallet'),
  saveWallet: (data) => ipcRenderer.invoke('save-wallet', data),
  
  // Security
  isElectron: true,
  platform: process.platform,
  
  // Remove listener
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
});

console.log('🔐 WEPO Desktop Wallet preload script loaded');