package com.wepo.wallet

import android.app.Application
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class WepoApplication : Application() {
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize any global configurations here
        setupSecurity()
    }
    
    private fun setupSecurity() {
        // Enable strict mode in debug builds
        if (BuildConfig.DEBUG) {
            // Add any debug-specific security configurations
        }
        
        // Configure network security
        // All network calls should use HTTPS in production
    }
}