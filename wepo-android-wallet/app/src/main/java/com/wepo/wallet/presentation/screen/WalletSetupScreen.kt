package com.wepo.wallet.presentation.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.itemsIndexed
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.wepo.wallet.presentation.theme.WepoPrimary
import com.wepo.wallet.presentation.viewmodel.WalletViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletSetupScreen(
    viewModel: WalletViewModel,
    onWalletCreated: () -> Unit
) {
    var setupMode by remember { mutableStateOf(SetupMode.CREATE) }
    var currentStep by remember { mutableStateOf(1) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var seedPhrase by remember { mutableStateOf("") }
    var generatedSeedPhrase by remember { mutableStateOf<List<String>>(emptyList()) }
    
    val isLoading by viewModel.isLoading.collectAsState()
    val error by viewModel.error.collectAsState()
    
    LaunchedEffect(error) {
        if (error != null) {
            // Handle error display
        }
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = if (setupMode == SetupMode.CREATE) "Create Wallet" else "Import Wallet",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            
            TextButton(
                onClick = {
                    setupMode = if (setupMode == SetupMode.CREATE) SetupMode.IMPORT else SetupMode.CREATE
                    currentStep = 1
                    username = ""
                    password = ""
                    confirmPassword = ""
                    seedPhrase = ""
                    generatedSeedPhrase = emptyList()
                }
            ) {
                Text(if (setupMode == SetupMode.CREATE) "Import" else "Create")
            }
        }
        
        Spacer(modifier = Modifier.height(32.dp))
        
        when (setupMode) {
            SetupMode.CREATE -> {
                CreateWalletFlow(
                    currentStep = currentStep,
                    username = username,
                    password = password,
                    confirmPassword = confirmPassword,
                    generatedSeedPhrase = generatedSeedPhrase,
                    isLoading = isLoading,
                    onUsernameChange = { username = it },
                    onPasswordChange = { password = it },
                    onConfirmPasswordChange = { confirmPassword = it },
                    onNextStep = { currentStep++ },
                    onGenerateSeedPhrase = {
                        generatedSeedPhrase = viewModel.generateSeedPhrase()
                    },
                    onCreateWallet = {
                        val seedPhraseString = generatedSeedPhrase.joinToString(" ")
                        viewModel.createWallet(username, password, seedPhraseString)
                    }
                )
            }
            SetupMode.IMPORT -> {
                ImportWalletFlow(
                    username = username,
                    password = password,
                    seedPhrase = seedPhrase,
                    isLoading = isLoading,
                    onUsernameChange = { username = it },
                    onPasswordChange = { password = it },
                    onSeedPhraseChange = { seedPhrase = it },
                    onImportWallet = {
                        viewModel.importWallet(username, password, seedPhrase.trim())
                    }
                )
            }
        }
        
        error?.let { errorMessage ->
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
            ) {
                Text(
                    text = errorMessage,
                    modifier = Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateWalletFlow(
    currentStep: Int,
    username: String,
    password: String,
    confirmPassword: String,
    generatedSeedPhrase: List<String>,
    isLoading: Boolean,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onConfirmPasswordChange: (String) -> Unit,
    onNextStep: () -> Unit,
    onGenerateSeedPhrase: () -> Unit,
    onCreateWallet: () -> Unit
) {
    when (currentStep) {
        1 -> {
            CreateWalletStep1(
                username = username,
                password = password,
                confirmPassword = confirmPassword,
                onUsernameChange = onUsernameChange,
                onPasswordChange = onPasswordChange,
                onConfirmPasswordChange = onConfirmPasswordChange,
                onNext = onNextStep
            )
        }
        2 -> {
            CreateWalletStep2(
                generatedSeedPhrase = generatedSeedPhrase,
                onGenerateSeedPhrase = onGenerateSeedPhrase,
                onNext = onNextStep
            )
        }
        3 -> {
            CreateWalletStep3(
                generatedSeedPhrase = generatedSeedPhrase,
                isLoading = isLoading,
                onCreateWallet = onCreateWallet
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateWalletStep1(
    username: String,
    password: String,
    confirmPassword: String,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onConfirmPasswordChange: (String) -> Unit,
    onNext: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        Icon(
            imageVector = Icons.Default.Person,
            contentDescription = null,
            tint = WepoPrimary,
            modifier = Modifier.size(64.dp)
        )
        
        Text(
            text = "Create Your Identity",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = "Choose a username and secure password for your wallet",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        OutlinedTextField(
            value = username,
            onValueChange = onUsernameChange,
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        
        OutlinedTextField(
            value = password,
            onValueChange = onPasswordChange,
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        
        OutlinedTextField(
            value = confirmPassword,
            onValueChange = onConfirmPasswordChange,
            label = { Text("Confirm Password") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Button(
            onClick = onNext,
            enabled = username.isNotEmpty() && 
                     password.isNotEmpty() && 
                     password.length >= 8 && 
                     password == confirmPassword,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Continue")
        }
    }
}

@Composable
fun CreateWalletStep2(
    generatedSeedPhrase: List<String>,
    onGenerateSeedPhrase: () -> Unit,
    onNext: () -> Unit
) {
    LaunchedEffect(Unit) {
        if (generatedSeedPhrase.isEmpty()) {
            onGenerateSeedPhrase()
        }
    }
    
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        Icon(
            imageVector = Icons.Default.Key,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(64.dp)
        )
        
        Text(
            text = "Your Recovery Phrase",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = "Write down these 12 words in order. You'll need them to recover your wallet.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        if (generatedSeedPhrase.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                LazyVerticalGrid(
                    columns = GridCells.Fixed(3),
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    itemsIndexed(generatedSeedPhrase) { index, word ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Row(
                                modifier = Modifier.padding(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "${index + 1}.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.width(20.dp)
                                )
                                Text(
                                    text = word,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }
                }
            }
        }
        
        Column(
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = onNext,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("I've Written It Down")
            }
            
            OutlinedButton(
                onClick = onGenerateSeedPhrase,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Generate New Phrase")
            }
        }
    }
}

@Composable
fun CreateWalletStep3(
    generatedSeedPhrase: List<String>,
    isLoading: Boolean,
    onCreateWallet: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        Icon(
            imageVector = Icons.Default.CheckCircle,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(64.dp)
        )
        
        Text(
            text = "Confirm Recovery Phrase",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = "Confirm you've saved your recovery phrase securely",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        // For simplicity, showing the phrase again
        // In production, implement verification UI
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Your Recovery Phrase:",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = generatedSeedPhrase.joinToString(" "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Button(
            onClick = onCreateWallet,
            enabled = !isLoading,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text("Create Wallet")
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportWalletFlow(
    username: String,
    password: String,
    seedPhrase: String,
    isLoading: Boolean,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onSeedPhraseChange: (String) -> Unit,
    onImportWallet: () -> Unit
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        Icon(
            imageVector = Icons.Default.Download,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(64.dp)
        )
        
        Text(
            text = "Import Your Wallet",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        
        Text(
            text = "Enter your 12-word recovery phrase and account details",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        OutlinedTextField(
            value = username,
            onValueChange = onUsernameChange,
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        
        OutlinedTextField(
            value = password,
            onValueChange = onPasswordChange,
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        
        OutlinedTextField(
            value = seedPhrase,
            onValueChange = onSeedPhraseChange,
            label = { Text("Recovery Phrase") },
            placeholder = { Text("Enter your 12-word recovery phrase") },
            minLines = 3,
            maxLines = 4,
            modifier = Modifier.fillMaxWidth()
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Button(
            onClick = onImportWallet,
            enabled = !isLoading && 
                     username.isNotEmpty() && 
                     password.isNotEmpty() && 
                     password.length >= 8 && 
                     seedPhrase.trim().split(" ").size == 12,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text("Import Wallet")
            }
        }
    }
}

enum class SetupMode {
    CREATE, IMPORT
}