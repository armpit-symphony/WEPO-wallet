package com.wepo.wallet.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.wepo.wallet.data.local.SecurityManager
import com.wepo.wallet.presentation.theme.*
import com.wepo.wallet.presentation.viewmodel.WalletViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SendTokenScreen(
    viewModel: WalletViewModel,
    onNavigateBack: () -> Unit
) {
    val balance by viewModel.balance.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val error by viewModel.error.collectAsState()
    val uiState by viewModel.uiState.collectAsState()
    
    var recipientAddress by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    var isPrivateMode by remember { mutableStateOf(false) }
    var showConfirmDialog by remember { mutableStateOf(false) }
    
    val scope = rememberCoroutineScope()
    val securityManager = remember { SecurityManager() }
    
    // Handle transaction success
    LaunchedEffect(uiState.lastTransactionSuccess) {
        if (uiState.lastTransactionSuccess) {
            viewModel.clearTransactionSuccess()
            onNavigateBack()
        }
    }
    
    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        TopAppBar(
            title = { Text("Send WEPO") },
            navigationIcon = {
                IconButton(onClick = onNavigateBack) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                }
            }
        )
        
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            // Header
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.ArrowUpward,
                    contentDescription = null,
                    tint = WepoPrimary,
                    modifier = Modifier.size(48.dp)
                )
                
                Text(
                    text = "Send WEPO",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Text(
                    text = "Available Balance: ${String.format("%.6f", balance)} WEPO",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Recipient Address
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Recipient Address",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        OutlinedTextField(
                            value = recipientAddress,
                            onValueChange = { recipientAddress = it },
                            label = { Text("Enter WEPO address") },
                            modifier = Modifier.weight(1f),
                            singleLine = false,
                            minLines = 2
                        )
                        
                        IconButton(
                            onClick = {
                                // QR Scanner functionality
                                // For now, show placeholder
                            }
                        ) {
                            Icon(
                                Icons.Default.QrCodeScanner,
                                contentDescription = "Scan QR",
                                tint = WepoPrimary
                            )
                        }
                    }
                    
                    if (recipientAddress.isNotEmpty() && !securityManager.validateWepoAddress(recipientAddress.trim())) {
                        Text(
                            text = "Invalid WEPO address format",
                            style = MaterialTheme.typography.bodySmall,
                            color = WepoError
                        )
                    }
                }
            }
            
            // Amount
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = "Amount",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    OutlinedTextField(
                        value = amount,
                        onValueChange = { amount = it },
                        label = { Text("0.000000") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    
                    // Percentage Buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        listOf(
                            "25%" to 0.25,
                            "50%" to 0.50,
                            "75%" to 0.75,
                            "Max" to 1.0
                        ).forEach { (label, percentage) ->
                            OutlinedButton(
                                onClick = {
                                    val calculatedAmount = balance * percentage
                                    amount = String.format("%.6f", calculatedAmount)
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(label)
                            }
                        }
                    }
                    
                    val amountValue = amount.toDoubleOrNull()
                    if (amountValue != null && amountValue > balance) {
                        Text(
                            text = "Insufficient balance",
                            style = MaterialTheme.typography.bodySmall,
                            color = WepoError
                        )
                    }
                }
            }
            
            // Privacy Mode
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
                            text = "Private Transaction",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        
                        Switch(
                            checked = isPrivateMode,
                            onCheckedChange = { isPrivateMode = it }
                        )
                    }
                    
                    if (isPrivateMode) {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = WepoAccent.copy(alpha = 0.1f))
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Icon(
                                        Icons.Default.Security,
                                        contentDescription = null,
                                        tint = WepoAccent
                                    )
                                    Text(
                                        text = "Enhanced Privacy Mode",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        color = WepoAccent
                                    )
                                }
                                
                                Text(
                                    text = "Your transaction will be mixed through quantum vaults for enhanced anonymity. Additional network fees may apply.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
            
            // Transaction Summary
            val amountValue = amount.toDoubleOrNull()
            val isValidTransaction = amountValue != null && 
                                   amountValue > 0 && 
                                   amountValue <= balance && 
                                   recipientAddress.isNotEmpty() && 
                                   securityManager.validateWepoAddress(recipientAddress.trim())
            
            if (isValidTransaction && amountValue != null) {
                TransactionSummaryCard(
                    amount = amountValue,
                    recipient = recipientAddress,
                    isPrivate = isPrivateMode,
                    fee = if (isPrivateMode) 0.001 else 0.0
                )
            }
            
            // Error Display
            error?.let { errorMessage ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = WepoError.copy(alpha = 0.1f))
                ) {
                    Text(
                        text = errorMessage,
                        modifier = Modifier.padding(16.dp),
                        color = WepoError,
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Send Button
            Button(
                onClick = { showConfirmDialog = true },
                enabled = isValidTransaction && !isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text("Send WEPO")
                }
            }
        }
    }
    
    // Confirmation Dialog
    if (showConfirmDialog && amountValue != null) {
        SendConfirmationDialog(
            amount = amountValue,
            recipient = recipientAddress,
            isPrivate = isPrivateMode,
            onConfirm = {
                scope.launch {
                    viewModel.sendTransaction(
                        recipientAddress.trim(),
                        amountValue,
                        isPrivateMode
                    )
                }
                showConfirmDialog = false
            },
            onDismiss = { showConfirmDialog = false }
        )
    }
}

@Composable
fun TransactionSummaryCard(
    amount: Double,
    recipient: String,
    isPrivate: Boolean,
    fee: Double
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Transaction Summary",
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
                        text = "Amount:",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${String.format("%.6f", amount)} WEPO",
                        fontWeight = FontWeight.Medium
                    )
                }
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Network Fee:",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "${String.format("%.6f", fee)} WEPO",
                        fontWeight = FontWeight.Medium,
                        color = if (fee == 0.0) WepoSuccess else MaterialTheme.colorScheme.onSurface
                    )
                }
                
                Divider()
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Total:",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "${String.format("%.6f", amount + fee)} WEPO",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                
                if (isPrivate) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            Icons.Default.VisibilityOff,
                            contentDescription = null,
                            tint = WepoAccent,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Private Transaction",
                            style = MaterialTheme.typography.bodySmall,
                            color = WepoAccent
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun SendConfirmationDialog(
    amount: Double,
    recipient: String,
    isPrivate: Boolean,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Confirm Transaction",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Send ${String.format("%.6f", amount)} WEPO to:",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                Text(
                    text = "${recipient.take(20)}...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                if (isPrivate) {
                    Text(
                        text = "This will be a private transaction.",
                        style = MaterialTheme.typography.bodySmall,
                        color = WepoAccent
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = onConfirm) {
                Text("Send")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}