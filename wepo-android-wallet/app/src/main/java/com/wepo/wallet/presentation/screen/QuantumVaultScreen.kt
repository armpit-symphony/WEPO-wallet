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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.wepo.wallet.data.model.VaultInfo
import com.wepo.wallet.presentation.theme.*
import com.wepo.wallet.presentation.viewmodel.WalletViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QuantumVaultScreen(
    viewModel: WalletViewModel
) {
    var showCreateVault by remember { mutableStateOf(false) }
    
    // Mock vault data for demonstration
    val vaults = remember {
        listOf(
            VaultInfo(
                id = "vault_1",
                vaultType = "privacy",
                status = "active",
                balance = 150.5,
                createdAt = System.currentTimeMillis() - 86400000 // 1 day ago
            ),
            VaultInfo(
                id = "vault_2",
                vaultType = "staking",
                status = "locked",
                balance = 1000.0,
                createdAt = System.currentTimeMillis() - 604800000 // 1 week ago
            )
        )
    }
    
    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        TopAppBar(
            title = { Text("Quantum Vault") },
            actions = {
                IconButton(onClick = { showCreateVault = true }) {
                    Icon(Icons.Default.Add, contentDescription = "Create Vault")
                }
            }
        )
        
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header
            item {
                QuantumVaultHeader()
            }
            
            // Create Vault Button
            item {
                Button(
                    onClick = { showCreateVault = true },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = WepoAccent)
                ) {
                    Icon(Icons.Default.Add, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Create New Vault")
                }
            }
            
            // Existing Vaults
            if (vaults.isEmpty()) {
                item {
                    EmptyVaultsCard()
                }
            } else {
                item {
                    Text(
                        text = "Your Vaults",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(vertical = 8.dp)
                    )
                }
                
                items(vaults) { vault ->
                    VaultCard(vault = vault)
                }
            }
            
            // Vault Information
            item {
                VaultInformationCard()
            }
        }
    }
    
    // Create Vault Dialog
    if (showCreateVault) {
        CreateVaultDialog(
            onDismiss = { showCreateVault = false },
            onCreateVault = { vaultType, amount ->
                // Handle vault creation
                showCreateVault = false
            }
        )
    }
}

@Composable
fun QuantumVaultHeader() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = WepoAccent.copy(alpha = 0.1f))
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = null,
                tint = WepoAccent,
                modifier = Modifier.size(48.dp)
            )
            
            Text(
                text = "Quantum Vault",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            
            Text(
                text = "Privacy-protected asset storage with quantum-resistant security",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun VaultCard(vault: VaultInfo) {
    var showVaultDetails by remember { mutableStateOf(false) }
    
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
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        imageVector = getVaultIcon(vault.vaultType),
                        contentDescription = null,
                        tint = getVaultColor(vault.vaultType),
                        modifier = Modifier.size(24.dp)
                    )
                    
                    Column {
                        Text(
                            text = vault.vaultType.replaceFirstChar { it.uppercase() },
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        
                        val dateFormat = SimpleDateFormat("MMM dd, yyyy", Locale.getDefault())
                        Text(
                            text = "Created: ${dateFormat.format(Date(vault.createdAt))}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                
                Column(
                    horizontalAlignment = Alignment.End
                ) {
                    Text(
                        text = "${String.format("%.2f", vault.balance)} WEPO",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                    
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = getStatusColor(vault.status).copy(alpha = 0.2f)
                        )
                    ) {
                        Text(
                            text = vault.status.replaceFirstChar { it.uppercase() },
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = getStatusColor(vault.status)
                        )
                    }
                }
            }
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = { showVaultDetails = true },
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Details")
                }
                
                Button(
                    onClick = { /* Handle vault action */ },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = getVaultColor(vault.vaultType))
                ) {
                    Text(if (vault.status == "active") "Deposit" else "Unlock")
                }
            }
        }
    }
    
    // Vault Details Dialog
    if (showVaultDetails) {
        VaultDetailsDialog(
            vault = vault,
            onDismiss = { showVaultDetails = false }
        )
    }
}

@Composable
fun EmptyVaultsCard() {
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
                imageVector = Icons.Default.LockOpen,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(48.dp)
            )
            
            Text(
                text = "No Vaults Created",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Text(
                text = "Create your first quantum vault to securely store and protect your assets with advanced privacy features.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun VaultInformationCard() {
    var expanded by remember { mutableStateOf(false) }
    
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
                    text = "About Quantum Vaults",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                IconButton(onClick = { expanded = !expanded }) {
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
                        text = "Quantum Vaults provide:",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium
                    )
                    
                    Column(
                        modifier = Modifier.padding(start = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        listOf(
                            "Quantum-resistant encryption",
                            "Zero-knowledge proof privacy",
                            "Multi-signature security",
                            "Time-locked asset protection",
                            "Anonymous transaction mixing"
                        ).forEach { feature ->
                            Text(
                                text = "• $feature",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    
                    Card(
                        colors = CardDefaults.cardColors(containerColor = WepoPrimary.copy(alpha = 0.1f))
                    ) {
                        Text(
                            text = "Your assets remain under your complete control while benefiting from advanced privacy and security features.",
                            modifier = Modifier.padding(12.dp),
                            style = MaterialTheme.typography.bodySmall,
                            color = WepoPrimary
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun CreateVaultDialog(
    onDismiss: () -> Unit,
    onCreateVault: (String, Double) -> Unit
) {
    var selectedVaultType by remember { mutableStateOf("privacy") }
    var initialDeposit by remember { mutableStateOf("") }
    
    val vaultTypes = listOf(
        "privacy" to "Privacy Vault" to "Enhanced anonymity and transaction mixing",
        "staking" to "Staking Vault" to "Earn rewards while securing the network"
    )
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Create Quantum Vault",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Vault Type Selection
                Text(
                    text = "Select Vault Type",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                vaultTypes.forEach { (type, title, description) ->
                    Card(
                        onClick = { selectedVaultType = type },
                        colors = CardDefaults.cardColors(
                            containerColor = if (selectedVaultType == type) 
                                WepoAccent.copy(alpha = 0.1f) 
                            else 
                                MaterialTheme.colorScheme.surfaceVariant
                        ),
                        border = if (selectedVaultType == type) 
                            androidx.compose.foundation.BorderStroke(2.dp, WepoAccent) 
                        else null
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = title,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                                
                                if (selectedVaultType == type) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = WepoAccent
                                    )
                                }
                            }
                            
                            Text(
                                text = description,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                
                // Initial Deposit
                Text(
                    text = "Initial Deposit",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                OutlinedTextField(
                    value = initialDeposit,
                    onValueChange = { initialDeposit = it },
                    label = { Text("Amount in WEPO") },
                    modifier = Modifier.fillMaxWidth()
                )
                
                Text(
                    text = "Minimum deposit: 10 WEPO",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val amount = initialDeposit.toDoubleOrNull()
                    if (amount != null && amount >= 10.0) {
                        onCreateVault(selectedVaultType, amount)
                    }
                },
                enabled = initialDeposit.toDoubleOrNull()?.let { it >= 10.0 } == true
            ) {
                Text("Create Vault")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun VaultDetailsDialog(
    vault: VaultInfo,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "${vault.vaultType.replaceFirstChar { it.uppercase() }} Vault",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "Vault Details Coming Soon",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
                
                // Placeholder for vault details
                Text(
                    text = "ID: ${vault.id}",
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    text = "Status: ${vault.status}",
                    style = MaterialTheme.typography.bodySmall
                )
                Text(
                    text = "Balance: ${vault.balance} WEPO",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

// Helper functions
private fun getVaultIcon(vaultType: String): ImageVector {
    return when (vaultType) {
        "privacy" -> Icons.Default.VisibilityOff
        "staking" -> Icons.Default.TrendingUp
        else -> Icons.Default.Lock
    }
}

private fun getVaultColor(vaultType: String): androidx.compose.ui.graphics.Color {
    return when (vaultType) {
        "privacy" -> WepoAccent
        "staking" -> WepoPrimary
        else -> MaterialTheme.coilorScheme.primary
    }
}

private fun getStatusColor(status: String): androidx.compose.ui.graphics.Color {
    return when (status) {
        "active" -> WepoSuccess
        "locked" -> WepoWarning
        "closed" -> WepoError
        else -> MaterialTheme.colorScheme.onSurface
    }
}