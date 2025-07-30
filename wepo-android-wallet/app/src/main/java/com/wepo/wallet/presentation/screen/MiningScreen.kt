package com.wepo.wallet.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.wepo.wallet.presentation.theme.*
import com.wepo.wallet.presentation.viewmodel.WalletViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MiningScreen(
    viewModel: WalletViewModel
) {
    val miningStatus by viewModel.miningStatus.collectAsState()
    val scope = rememberCoroutineScope()
    
    var showMiningInfo by remember { mutableStateOf(false) }
    
    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        TopAppBar(
            title = { Text("Mining") },
            actions = {
                IconButton(
                    onClick = {
                        scope.launch {
                            viewModel.refreshMiningStatus()
                        }
                    }
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                }
            }
        )
        
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Mining Status Card
            item {
                MiningStatusCard(
                    isActive = miningStatus.isActive,
                    hashrate = miningStatus.hashrate,
                    onToggleMining = {
                        scope.launch {
                            viewModel.toggleMining()
                        }
                    }
                )
            }
            
            // Mining Statistics
            if (miningStatus.isActive) {
                item {
                    MiningStatisticsCard(
                        hashrate = miningStatus.hashrate,
                        blocksFound = miningStatus.blocksFound,
                        earnings = miningStatus.earnings
                    )
                }
            }
            
            // Mining Information
            item {
                MiningInformationCard(
                    expanded = showMiningInfo,
                    onExpandedChange = { showMiningInfo = it }
                )
            }
            
            // Reward Structure
            item {
                RewardStructureCard()
            }
        }
    }
}

@Composable
fun MiningStatusCard(
    isActive: Boolean,
    hashrate: Double,
    onToggleMining: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isActive) 
                WepoSuccess.copy(alpha = 0.1f) 
            else 
                MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Memory,
                        contentDescription = null,
                        tint = if (isActive) WepoSuccess else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(24.dp)
                    )
                    Text(
                        text = "Mining Status",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                
                // Status Indicator
                Box(
                    modifier = Modifier.size(12.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        drawCircle(
                            color = if (isActive) Color.Green else Color.Red,
                            radius = size.minDimension / 2
                        )
                    }
                }
            }
            
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = if (isActive) "Mining Active" else "Mining Stopped",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    color = if (isActive) WepoSuccess else MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                if (isActive) {
                    Text(
                        text = "Earning WEPO tokens for network security",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                }
            }
            
            Button(
                onClick = onToggleMining,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isActive) WepoError else WepoSuccess
                )
            ) {
                Icon(
                    imageVector = if (isActive) Icons.Default.Stop else Icons.Default.PlayArrow,
                    contentDescription = null
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (isActive) "Stop Mining" else "Start Mining")
            }
        }
    }
}

@Composable
fun MiningStatisticsCard(
    hashrate: Double,
    blocksFound: Int,
    earnings: Double
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "Mining Statistics",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        text = "Hashrate",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${String.format("%.2f", hashrate)} H/s",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium
                    )
                }
                
                Column(
                    horizontalAlignment = Alignment.End
                ) {
                    Text(
                        text = "Blocks Found",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = blocksFound.toString(),
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        text = "Total Earnings",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${String.format("%.6f", earnings)} WEPO",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        color = WepoSuccess
                    )
                }
                
                Column(
                    horizontalAlignment = Alignment.End
                ) {
                    Text(
                        text = "Est. Daily",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${String.format("%.6f", hashrate * 0.001)} WEPO",
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        color = WepoPrimary
                    )
                }
            }
        }
    }
}

@Composable
fun MiningInformationCard(
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Mining Information",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                IconButton(onClick = { onExpandedChange(!expanded) }) {
                    Icon(
                        if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = null,
                        tint = WepoPrimary
                    )
                }
            }
            
            if (expanded) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Mobile Mining Details:",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                    
                    Column(
                        modifier = Modifier.padding(start = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Text(
                            text = "• Optimized for mobile devices",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "• Low battery consumption",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "• Rewards based on contribution",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = "• Network security participation",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Card(
                        colors = CardDefaults.cardColors(containerColor = WepoWarning.copy(alpha = 0.1f))
                    ) {
                        Text(
                            text = "Note: Mining runs in background when app is active. Performance may vary based on device capabilities.",
                            style = MaterialTheme.typography.bodySmall,
                            color = WepoWarning,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun RewardStructureCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Reward Structure",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Block Reward:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "50 WEPO",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = WepoSuccess
                    )
                }
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Miner Share:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "25%",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = WepoPrimary
                    )
                }
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Network Fee:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = "0 WEPO",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = WepoSuccess
                    )
                }
            }
        }
    }
}

// Canvas composable for drawing circles
@Composable
fun Canvas(modifier: Modifier, onDraw: androidx.compose.ui.graphics.drawscope.DrawScope.() -> Unit) {
    androidx.compose.foundation.Canvas(modifier = modifier, onDraw = onDraw)
}