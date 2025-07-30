import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var selectedTab = 0
    @State private var showingSettings = false
    
    var body: some View {
        TabView(selection: $selectedTab) {
            // Wallet Tab
            WalletOverviewView()
                .tabItem {
                    Image(systemName: "wallet.pass.fill")
                    Text("Wallet")
                }
                .tag(0)
            
            // Bitcoin Tab
            BitcoinView()
                .tabItem {
                    Image(systemName: "bitcoinsign.circle.fill")
                    Text("Bitcoin")
                }
                .tag(1)
            
            // Mining Tab
            MiningView()
                .tabItem {
                    Image(systemName: "cpu.fill")
                    Text("Mining")
                }
                .tag(2)
            
            // Vault Tab
            QuantumVaultView()
                .tabItem {
                    Image(systemName: "lock.shield.fill")
                    Text("Vault")
                }
                .tag(3)
        }
        .navigationBarBackButtonHidden(true)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: {
                    showingSettings = true
                }) {
                    Image(systemName: "gearshape.fill")
                }
            }
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView()
        }
    }
}

struct WalletOverviewView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var showingSendView = false
    @State private var showingReceiveView = false
    @State private var isPrivateMode = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Balance Card
                    VStack(spacing: 16) {
                        HStack {
                            Text("WEPO Balance")
                                .font(.headline)
                                .foregroundColor(.secondary)
                            
                            Spacer()
                            
                            Toggle("Private Mode", isOn: $isPrivateMode)
                                .labelsHidden()
                        }
                        
                        HStack {
                            Text("\(walletManager.balance, specifier: "%.6f")")
                                .font(.largeTitle.bold())
                                .fontDesign(.monospaced)
                            
                            Text("WEPO")
                                .font(.title2)
                                .foregroundColor(.secondary)
                        }
                        
                        Text("≈ $\(walletManager.balance * 0.01, specifier: "%.2f") USD")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(16)
                    
                    // Action Buttons
                    HStack(spacing: 16) {
                        Button(action: {
                            showingSendView = true
                        }) {
                            VStack(spacing: 8) {
                                Image(systemName: "arrow.up.circle.fill")
                                    .font(.title)
                                Text("Send")
                                    .font(.subheadline)
                            }
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.blue)
                            .cornerRadius(12)
                        }
                        
                        Button(action: {
                            showingReceiveView = true
                        }) {
                            VStack(spacing: 8) {
                                Image(systemName: "arrow.down.circle.fill")
                                    .font(.title)
                                Text("Receive")
                                    .font(.subheadline)
                            }
                            .foregroundColor(.white)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.green)
                            .cornerRadius(12)
                        }
                    }
                    
                    // Network Status
                    NetworkStatusCard()
                    
                    // Recent Transactions
                    TransactionHistoryView()
                }
                .padding()
            }
            .navigationTitle("Dashboard")
            .refreshable {
                await refreshData()
            }
        }
        .sheet(isPresented: $showingSendView) {
            SendTokenView()
        }
        .sheet(isPresented: $showingReceiveView) {
            ReceiveTokenView()
        }
    }
    
    @MainActor
    private func refreshData() async {
        await walletManager.refreshBalance()
        await walletManager.refreshTransactions()
    }
}

struct NetworkStatusCard: View {
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Network Status")
                .font(.headline)
            
            HStack {
                Circle()
                    .fill(walletManager.isConnected ? Color.green : Color.red)
                    .frame(width: 12, height: 12)
                
                Text(walletManager.isConnected ? "Connected" : "Disconnected")
                    .font(.subheadline)
                
                Spacer()
                
                Text("Block: \(walletManager.currentBlock)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Staking")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text("\(walletManager.stakingBalance, specifier: "%.2f") WEPO")
                        .font(.subheadline.bold())
                }
                
                Spacer()
                
                VStack(alignment: .trailing, spacing: 4) {
                    Text("Rewards")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text("\(walletManager.stakingRewards, specifier: "%.6f") WEPO")
                        .font(.subheadline.bold())
                        .foregroundColor(.green)
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct TransactionHistoryView: View {
    @EnvironmentObject var walletManager: WalletManager
    
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Recent Transactions")
                    .font(.headline)
                
                Spacer()
                
                Button("View All") {
                    // Navigate to full transaction history
                }
                .font(.subheadline)
                .foregroundColor(.blue)
            }
            
            if walletManager.transactions.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.title2)
                        .foregroundColor(.secondary)
                    
                    Text("No transactions yet")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 32)
            } else {
                LazyVStack(spacing: 12) {
                    ForEach(walletManager.transactions.prefix(5), id: \.id) { transaction in
                        TransactionRowView(transaction: transaction)
                    }
                }
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

struct TransactionRowView: View {
    let transaction: Transaction
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: transaction.type == .sent ? "arrow.up.circle.fill" : "arrow.down.circle.fill")
                .font(.title2)
                .foregroundColor(transaction.type == .sent ? .red : .green)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(transaction.type == .sent ? "Sent WEPO" : "Received WEPO")
                    .font(.subheadline.bold())
                
                Text(transaction.timestamp.formatted(date: .abbreviated, time: .shortened))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            VStack(alignment: .trailing, spacing: 4) {
                Text("\(transaction.type == .sent ? "-" : "+")\(transaction.amount, specifier: "%.6f")")
                    .font(.subheadline.bold())
                    .foregroundColor(transaction.type == .sent ? .red : .green)
                
                Text(transaction.status.rawValue.capitalized)
                    .font(.caption)
                    .foregroundColor(transaction.status == .confirmed ? .green : .orange)
            }
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    DashboardView()
        .environmentObject(WalletManager())
}