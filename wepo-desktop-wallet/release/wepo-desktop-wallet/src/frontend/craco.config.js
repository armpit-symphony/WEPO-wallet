const webpack = require('webpack');

// Load configuration from environment or use defaults
const config = {
  disableHotReload: process.env.DISABLE_HOT_RELOAD === 'true',
};

module.exports = {
  webpack: {
    configure: (webpackConfig) => {
      // Add Node.js polyfills for browser compatibility - specifically for crypto libraries
      webpackConfig.resolve.fallback = {
        ...webpackConfig.resolve.fallback,
        "buffer": require.resolve("buffer"),
        "crypto": require.resolve("crypto-browserify"),
        "stream": require.resolve("stream-browserify"),
        "assert": require.resolve("assert"),
        "http": require.resolve("stream-http"),
        "https": require.resolve("https-browserify"),
        "os": require.resolve("os-browserify"),
        "url": require.resolve("url"),
        "zlib": require.resolve("browserify-zlib"),
        "path": require.resolve("path-browserify"),
        "process": require.resolve("process/browser"),
        "fs": false,
        "net": false,
        "tls": false,
        // Additional polyfills needed for bip39
        "util": require.resolve("util"),
        "vm": false,
        "child_process": false
      };

      // Add webpack plugins for global polyfills - CRITICAL for bip39
      webpackConfig.plugins.push(
        new webpack.ProvidePlugin({
          Buffer: ['buffer', 'Buffer'],
          process: 'process/browser',
        })
      );
      
      // Define global variables for crypto libraries
      webpackConfig.plugins.push(
        new webpack.DefinePlugin({
          global: 'globalThis',
          'process.env.NODE_DEBUG': JSON.stringify(process.env.NODE_DEBUG || ''),
        })
      );
      
      // Disable hot reload completely if environment variable is set
      if (config.disableHotReload) {
        // Remove hot reload related plugins
        webpackConfig.plugins = webpackConfig.plugins.filter((plugin) => {
          return !plugin.constructor.name.includes('HotModuleReplacementPlugin');
        });
        
        // Remove hot reload from entry points
        if (webpackConfig.entry && Array.isArray(webpackConfig.entry)) {
          webpackConfig.entry = webpackConfig.entry.filter(entry => 
            !entry.includes('webpack-hot-middleware') && 
            !entry.includes('react-hot-loader')
          );
        }
      }
      
      return webpackConfig;
    },
  },
};
