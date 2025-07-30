package com.wepo.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.core.view.WindowCompat
import androidx.hilt.navigation.compose.hiltViewModel
import com.wepo.wallet.presentation.navigation.WepoNavigation
import com.wepo.wallet.presentation.theme.WepoWalletTheme
import com.wepo.wallet.presentation.viewmodel.WalletViewModel
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Enable edge-to-edge display
        enableEdgeToEdge()
        
        // Configure window for secure content
        WindowCompat.setDecorFitsSystemWindows(window, false)
        
        setContent {
            WepoWalletTheme {
                WepoApp()
            }
        }
    }
}

@Composable
fun WepoApp() {
    val walletViewModel: WalletViewModel = hiltViewModel()
    
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background
    ) {
        Scaffold { paddingValues ->
            WepoNavigation(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                walletViewModel = walletViewModel
            )
        }
    }
}