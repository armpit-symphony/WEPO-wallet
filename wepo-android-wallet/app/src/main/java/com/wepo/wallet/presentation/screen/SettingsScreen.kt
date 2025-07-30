package com.wepo.wallet.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.compose.ui.platform.LocalContext
import com.wepo.wallet.data.local.SecurityManager
import com.wepo.wallet.presentation.theme.*
import com.wepo.wallet.presentation.viewmodel.WalletViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: WalletViewModel,
    onNavigateBack: () -> Unit
) {
    val walletState by viewModel.walletState.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val clipboardManager = LocalClipboardManager.current
    val securityManager = remember { SecurityManager(context) }
    
    var showBackupPhrase by remember { mutableStateOf(false) }
    var showDeleteConfirmation by remember { mutableStateOf(false) }
    var biometricsEnabled by remember { mutableStateOf(true) }
    var notificationsEnabled by remember { mutableStateOf(true) }
    var privateByDefault by remember { mutableStateOf(false) }
    
    Column(
        modifier = Modifier.fillMaxSize()
    ) {
        TopAppBar(
            title = { Text("Settings") },
            navigationIcon = {
                IconButton(onClick = onNavigateBack) {
                    Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                }
            }
        )
        
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Profile Section
            item {
                ProfileCard(
                    username = walletState?.username ?: "WEPO User"
                )
            }
            
            // Security Section
            item {
                SettingsSection(title = "Security") {
                    SettingsItem(
                        icon = Icons.Default.Key,
                        title = "Backup Recovery Phrase",
                        subtitle = "View your 12-word recovery phrase",
                        iconColor = WepoWarning,
                        onClick = { showBackupPhrase = true }
                    )
                    
                    SettingsToggleItem(
                        icon = Icons.Default.Fingerprint,
                        title = "Biometric Authentication",
                        subtitle = "Use fingerprint or face unlock",
                        iconColor = WepoSuccess,
                        checked = biometricsEnabled,
                        onCheckedChange = { biometricsEnabled = it },
                        enabled = securityManager.isBiometricAvailable()
                    )
                    
                    SettingsItem(
                        icon = Icons.Default.Lock,
                        title = "Change Password",
                        subtitle = "Update your wallet password",
                        iconColor = WepoPrimary,
                        onClick = { /* Handle password change */ }
                    )
                }
            }
            
            // Privacy Section
            item {
                SettingsSection(title = "Privacy") {
                    SettingsToggleItem(
                        icon = Icons.Default.VisibilityOff,
                        title = "Private by Default",
                        subtitle = "Use privacy mode for all transactions",
                        iconColor = WepoAccent,
                        checked = privateByDefault,
                        onCheckedChange = { privateByDefault = it }
                    )
                    
                    SettingsItem(
                        icon = Icons.Default.Shield,
                        title = "Privacy Settings",
                        subtitle = "Configure advanced privacy options",
                        iconColor = WepoAccent,
                        onClick = { /* Handle privacy settings */ }
                    )
                }
            }
            
            // Notifications Section
            item {
                SettingsSection(title = "Notifications") {
                    SettingsToggleItem(
                        icon = Icons.Default.Notifications,
                        title = "Push Notifications",
                        subtitle = "Receive transaction and mining alerts",
                        iconColor = WepoError,
                        checked = notificationsEnabled,
                        onCheckedChange = { notificationsEnabled = it }
                    )
                }
            }
            
            // Network Section
            item {
                SettingsSection(title = "Network") {
                    SettingsItem(
                        icon = Icons.Default.Language,
                        title = "Network Settings",
                        subtitle = "Configure API endpoints",
                        iconColor = WepoPrimary,
                        onClick = { /* Handle network settings */ }
                    )
                    
                    SettingsItem(
                        icon = Icons.Default.Info,
                        title = "Network Status",
                        subtitle = "View blockchain connection info",
                        iconColor = WepoSuccess,
                        onClick = { /* Handle network status */ }
                    )
                }
            }
            
            // Support Section
            item {
                SettingsSection(title = "Support") {
                    SettingsItem(
                        icon = Icons.Default.Help,
                        title = "Help & FAQ",
                        subtitle = "Get help using WEPO Wallet",
                        iconColor = WepoPrimary,
                        onClick = { /* Handle help */ }
                    )
                    
                    SettingsItem(
                        icon = Icons.Default.Email,
                        title = "Contact Support",
                        subtitle = "Reach out to our support team",
                        iconColor = WepoSuccess,
                        onClick = { /* Handle contact support */ }
                    )
                    
                    SettingsItem(
                        icon = Icons.Default.Description,
                        title = "Terms & Privacy",
                        subtitle = "View our terms and privacy policy",
                        iconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        onClick = { /* Handle terms and privacy */ }
                    )
                }
            }
            
            // App Information Section
            item {
                SettingsSection(title = "App Information") {
                    InfoItem(label = "Version", value = "1.0.0")
                    InfoItem(label = "Build", value = "2024.01.001")
                }
            }
            
            // Danger Zone Section
            item {
                SettingsSection(title = "Danger Zone") {
                    SettingsItem(
                        icon = Icons.Default.Logout,
                        title = "Logout",
                        subtitle = "Sign out of your wallet",
                        iconColor = WepoWarning,
                        onClick = {
                            viewModel.logout()
                            onNavigateBack()
                        }
                    )
                    
                    SettingsItem(
                        icon = Icons.Default.Delete,
                        title = "Delete Wallet",
                        subtitle = "Permanently delete this wallet",
                        iconColor = WepoError,
                        onClick = { showDeleteConfirmation = true }
                    )
                }
            }
        }
    }
    
    // Backup Phrase Dialog
    if (showBackupPhrase) {
        BackupPhraseDialog(
            viewModel = viewModel,
            securityManager = securityManager,
            onDismiss = { showBackupPhrase = false },
            onCopySeedPhrase = { seedPhrase ->
                clipboardManager.setText(AnnotatedString(seedPhrase))
            }
        )
    }
    
    // Delete Confirmation Dialog
    if (showDeleteConfirmation) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirmation = false },
            title = {
                Text(
                    text = "Delete Wallet",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Text(
                    text = "This action cannot be undone. Make sure you have backed up your recovery phrase.",
                    style = MaterialTheme.typography.bodyMedium
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteWallet()
                        onNavigateBack()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = WepoError)
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirmation = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
fun ProfileCard(username: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Card(
                modifier = Modifier.size(50.dp),
                shape = CircleShape,
                colors = CardDefaults.cardColors(containerColor = WepoPrimary)
            ) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = username.firstOrNull()?.uppercase() ?: "W",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = androidx.compose.ui.graphics.Color.White
                    )
                }
            }
            
            Column {
                Text(
                    text = username,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "WEPO Wallet",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun SettingsSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            
            content()
        }
    }
}

@Composable
fun SettingsItem(
    icon: ImageVector,
    title: String,
    subtitle: String,
    iconColor: androidx.compose.ui.graphics.Color,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = iconColor,
                modifier = Modifier.size(24.dp)
            )
            
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

@Composable
fun SettingsToggleItem(
    icon: ImageVector,
    title: String,
    subtitle: String,
    iconColor: androidx.compose.ui.graphics.Color,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (enabled) iconColor else iconColor.copy(alpha = 0.5f),
                modifier = Modifier.size(24.dp)
            )
            
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = if (enabled) 1f else 0.5f)
                )
            }
            
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                enabled = enabled
            )
        }
    }
}

@Composable
fun InfoItem(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun BackupPhraseDialog(
    viewModel: WalletViewModel,
    securityManager: SecurityManager,
    onDismiss: () -> Unit,
    onCopySeedPhrase: (String) -> Unit
) {
    var seedPhrase by remember { mutableStateOf<String?>(null) }
    var isLoading by remember { mutableStateOf(true) }
    var hasAuthenticated by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    LaunchedEffect(hasAuthenticated) {
        if (hasAuthenticated && seedPhrase == null) {
            scope.launch {
                try {
                    val phrase = viewModel.getSeedPhrase()
                    seedPhrase = phrase
                    isLoading = false
                } catch (e: Exception) {
                    errorMessage = "Failed to load recovery phrase: ${e.message}"
                    isLoading = false
                }
            }
        }
    }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Recovery Phrase",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                when {
                    !hasAuthenticated -> {
                        AuthenticationPrompt(
                            securityManager = securityManager,
                            onAuthenticated = { hasAuthenticated = true },
                            onError = { errorMessage = it }
                        )
                    }
                    isLoading -> {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            CircularProgressIndicator()
                            Text("Loading recovery phrase...")
                        }
                    }
                    errorMessage != null -> {
                        Text(
                            text = errorMessage!!,
                            color = WepoError,
                            textAlign = TextAlign.Center
                        )
                    }
                    seedPhrase != null -> {
                        SeedPhraseDisplay(
                            seedPhrase = seedPhrase!!,
                            onCopy = { onCopySeedPhrase(seedPhrase!!) }
                        )
                    }
                }
            }
        },
        confirmButton = {
            if (seedPhrase != null) {
                Button(onClick = { onCopySeedPhrase(seedPhrase!!) }) {
                    Text("Copy to Clipboard")
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

@Composable
fun AuthenticationPrompt(
    securityManager: SecurityManager,
    onAuthenticated: () -> Unit,
    onError: (String) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Icon(
            Icons.Default.Fingerprint,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = WepoPrimary
        )
        
        Text(
            text = "Authentication Required",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = "Please authenticate to view your recovery phrase",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        Button(
            onClick = {
                scope.launch {
                    try {
                        val success = securityManager.authenticateWithBiometrics(
                            context as FragmentActivity,
                            "Access Recovery Phrase",
                            "Authenticate to view your wallet recovery phrase"
                        )
                        if (success) {
                            onAuthenticated()
                        }
                    } catch (e: Exception) {
                        onError("Authentication failed: ${e.message}")
                    }
                }
            }
        ) {
            Text("Authenticate")
        }
    }
}

@Composable
fun SeedPhraseDisplay(
    seedPhrase: String,
    onCopy: () -> Unit
) {
    val words = seedPhrase.split(" ")
    
    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Your 12-Word Recovery Phrase",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center
        )
        
        Text(
            text = "Write down these words in order and store them safely. Anyone with these words can access your wallet.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )
        
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            LazyVerticalGrid(
                columns = GridCells.Fixed(3),
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(words.size) { index ->
                    Card {
                        Row(
                            modifier = Modifier.padding(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "${index + 1}.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = words[index],
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }
                }
            }
        }
        
        Card(
            colors = CardDefaults.cardColors(containerColor = WepoError.copy(alpha = 0.1f))
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = null,
                        tint = WepoError
                    )
                    Text(
                        text = "Security Warning",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = WepoError
                    )
                }
                
                listOf(
                    "Never share your recovery phrase with anyone",
                    "Store it offline in a secure location",
                    "Don't save it on your phone or computer",
                    "Anyone with these words controls your wallet"
                ).forEach { warning ->
                    Text(
                        text = "• $warning",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

// Imports for LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.text.selection.SelectionContainer