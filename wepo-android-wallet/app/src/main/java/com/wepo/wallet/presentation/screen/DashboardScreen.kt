package com.wepo.wallet.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.wepo.wallet.data.model.Transaction
import com.wepo.wallet.data.model.TransactionType
import com.wepo.wallet.presentation.theme.*
import com.wepo.wallet.presentation.viewmodel.WalletViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: WalletViewModel,
    onNavigateToSend: () -> Unit,
    onNavigateToReceive: () -> Unit,
    onNavigateToSettings: () -> Unit
) {
    val balance by viewModel.balance.collectAsState()
    val transactions by viewModel.transactions.collectAsState()
    val networkStatus by viewModel.networkStatus.collectAsState()
    val stakingInfo by viewModel.stakingInfo.collectAsState()
    val walletState by viewModel.walletState.collectAsState()
    val isConnected by viewModel.isConnected.collectAsState()
    
    var isPrivateMode by remember { mutableStateOf(false) }
    
    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        // Top App Bar
        TopAppBar(
            title = { Text("Dashboard") },
            actions = {
                IconButton(onClick = onNavigateToSettings) {
                    Icon(Icons.Default.Settings, contentDescription = "Settings")
                }
            }
        )
        
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Balance Card
            item {
                BalanceCard(
                    balance = balance,
                    isPrivateMode = isPrivateMode,
                    onPrivateModeToggle = { isPrivateMode = it },
                    onSend = onNavigateToSend,
                    onReceive = onNavigateToReceive
                )
            }
            
            // Network Status Card
            item {
                NetworkStatusCard(
                    isConnected = isConnected,
                    currentBlock = networkStatus.currentBlock,
                    stakingBalance = stakingInfo.stakedAmount,
                    stakingRewards = stakingInfo.rewards
                )
            }
            
            // Transaction History
            item {
                Text(
                    text = "Recent Transactions",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }
            
            if (transactions.isEmpty()) {
                item {
                    EmptyTransactionsCard()
                }
            } else {
                items(transactions.take(5)) { transaction ->
                    TransactionItem(transaction = transaction)
                }
                
                if (transactions.size > 5) {
                    item {
                        TextButton(
                            onClick = { /* Navigate to full transaction history */ },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("View All Transactions")
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun BalanceCard(
    balance: Double,
    isPrivateMode: Boolean,
    onPrivateModeToggle: (Boolean) -> Unit,
    onSend: () -> Unit,
    onReceive: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "WEPO Balance",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
                
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Private",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                    Switch(
                        checked = isPrivateMode,
                        onCheckedChange = onPrivateModeToggle
                    )
                }
            }
            
            // Balance Display
            Row(
                verticalAlignment = Alignment.Bottom,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = String.format("%.6f", balance),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
                Text(
                    text = "WEPO",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
                )
            }
            
            Text(
                text = "≈ $${String.format("%.2f", balance * 0.01)} USD",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f)
            )
            
            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = onSend,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = WepoSuccess)
                ) {
                    Icon(Icons.Default.ArrowUpward, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Send")
                }
                
                Button(
                    onClick = onReceive,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = WepoPrimary)
                ) {
                    Icon(Icons.Default.ArrowDownward, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Receive")
                }
            }
        }
    }
}

@Composable
fun NetworkStatusCard(
    isConnected: Boolean,
    currentBlock: Int,
    stakingBalance: Double,
    stakingRewards: Double
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Network Status",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Canvas(modifier = Modifier.fillMaxSize()) { 
                            drawCircle(
                                color = if (isConnected) Color.Green else Color.Red,
                                radius = size.minDimension / 2
                            )
                        }
                    }
                    Text(
                        text = if (isConnected) "Connected" else "Disconnected",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                
                Text(
                    text = "Block: $currentBlock",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Staking Info
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        text = "Staking",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${String.format("%.2f", stakingBalance)} WEPO",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                }
                
                Column(
                    horizontalAlignment = Alignment.End
                ) {
                    Text(
                        text = "Rewards",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${String.format("%.6f", stakingRewards)} WEPO",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = WepoSuccess
                    )
                }
            }
        }
    }
}

@Composable
fun TransactionItem(transaction: Transaction) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Transaction Icon
            val (icon, iconColor) = when (transaction.type) {
                TransactionType.SENT -> Icons.Default.ArrowUpward to WepoError
                TransactionType.RECEIVED -> Icons.Default.ArrowDownward to WepoSuccess
            }
            
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = iconColor,
                modifier = Modifier.size(24.dp)
            )
            
            // Transaction Details
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = if (transaction.type == TransactionType.SENT) "Sent WEPO" else "Received WEPO",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                
                val dateFormat = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
                Text(
                    text = dateFormat.format(Date(transaction.timestamp)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Amount and Status
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = "${if (transaction.type == TransactionType.SENT) "-" else "+"}{String.format("%.6f", transaction.amount)}",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = if (transaction.type == TransactionType.SENT) WepoError else WepoSuccess
                )
                
                Text(
                    text = transaction.status.name.lowercase().replaceFirstChar { it.uppercase() },
                    style = MaterialTheme.typography.bodySmall,
                    color = when (transaction.status.name) {
                        "CONFIRMED" -> WepoSuccess
                        "PENDING" -> WepoWarning
                        else -> WepoError
                    }
                )
            }
        }
    }
}

@Composable
fun EmptyTransactionsCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Icon(
                imageVector = Icons.Default.History,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(48.dp)
            )
            
            Text(
                text = "No transactions yet",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Text(
                text = "Your transaction history will appear here once you start sending or receiving WEPO",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

// Canvas composable for drawing circles
@Composable
fun Canvas(modifier: Modifier, onDraw: androidx.compose.ui.graphics.drawscope.DrawScope.() -> Unit) {
    androidx.compose.foundation.Canvas(modifier = modifier, onDraw = onDraw)
}