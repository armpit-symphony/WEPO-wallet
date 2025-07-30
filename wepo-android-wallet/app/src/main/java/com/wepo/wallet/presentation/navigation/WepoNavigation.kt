package com.wepo.wallet.presentation.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.wepo.wallet.presentation.screen.*
import com.wepo.wallet.presentation.viewmodel.WalletViewModel

sealed class Screen(val route: String, val title: String, val icon: ImageVector) {
    object Wallet : Screen("wallet", "Wallet", Icons.Default.AccountBalanceWallet)
    object Bitcoin : Screen("bitcoin", "Bitcoin", Icons.Default.CurrencyBitcoin)
    object Mining : Screen("mining", "Mining", Icons.Default.Memory)
    object Vault : Screen("vault", "Vault", Icons.Default.Security)
}

val bottomNavItems = listOf(
    Screen.Wallet,
    Screen.Bitcoin,
    Screen.Mining,
    Screen.Vault
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WepoNavigation(
    modifier: Modifier = Modifier,
    walletViewModel: WalletViewModel
) {
    val navController = rememberNavController()
    val hasWallet by walletViewModel.hasWallet.collectAsState()
    
    if (!hasWallet) {
        WalletSetupScreen(
            viewModel = walletViewModel,
            onWalletCreated = {
                // Navigation handled by state change
            }
        )
    } else {
        Scaffold(
            bottomBar = {
                NavigationBar {
                    val navBackStackEntry by navController.currentBackStackEntryAsState()
                    val currentDestination = navBackStackEntry?.destination
                    
                    bottomNavItems.forEach { screen ->
                        NavigationBarItem(
                            icon = { Icon(screen.icon, contentDescription = screen.title) },
                            label = { Text(screen.title) },
                            selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                            onClick = {
                                navController.navigate(screen.route) {
                                    popUpTo(navController.graph.findStartDestination().id) {
                                        saveState = true
                                    }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        )
                    }
                }
            }
        ) { innerPadding ->
            NavHost(
                navController = navController,
                startDestination = Screen.Wallet.route,
                modifier = modifier.padding(innerPadding)
            ) {
                composable(Screen.Wallet.route) {
                    DashboardScreen(
                        viewModel = walletViewModel,
                        onNavigateToSend = {
                            navController.navigate("send")
                        },
                        onNavigateToReceive = {
                            navController.navigate("receive")
                        },
                        onNavigateToSettings = {
                            navController.navigate("settings")
                        }
                    )
                }
                
                composable(Screen.Bitcoin.route) {
                    BitcoinScreen(viewModel = walletViewModel)
                }
                
                composable(Screen.Mining.route) {
                    MiningScreen(viewModel = walletViewModel)
                }
                
                composable(Screen.Vault.route) {
                    QuantumVaultScreen(viewModel = walletViewModel)
                }
                
                composable("send") {
                    SendTokenScreen(
                        viewModel = walletViewModel,
                        onNavigateBack = { navController.popBackStack() }
                    )
                }
                
                composable("receive") {
                    ReceiveTokenScreen(
                        viewModel = walletViewModel,
                        onNavigateBack = { navController.popBackStack() }
                    )
                }
                
                composable("settings") {
                    SettingsScreen(
                        viewModel = walletViewModel,
                        onNavigateBack = { navController.popBackStack() }
                    )
                }
            }
        }
    }
}