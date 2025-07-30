import SwiftUI

struct MiningView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var isMining = false
    @State private var hashrate: Double = 0.0
    @State private var blocksFound = 0
    @State private var earnings: Double = 0.0
    @State private var showingMiningInfo = false
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Mining Status Card
                    VStack(spacing: 16) {
                        HStack {
                            Image(systemName: "cpu.fill")
                                .font(.title2)
                                .foregroundColor(isMining ? .green : .gray)
                            
                            Text("Mining Status")
                                .font(.headline)
                            
                            Spacer()
                            
                            Circle()
                                .fill(isMining ? Color.green : Color.red)
                                .frame(width: 12, height: 12)
                        }
                        
                        VStack(spacing: 8) {
                            Text(isMining ? "Mining Active" : "Mining Stopped")
                                .font(.title2.bold())
                                .foregroundColor(isMining ? .green : .secondary)
                            
                            if isMining {
                                Text("Earning WEPO tokens for network security")
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                                    .multilineTextAlignment(.center)
                            }
                        }
                        
                        // Mining Toggle Button
                        Button(action: {
                            toggleMining()
                        }) {
                            Text(isMining ? "Stop Mining" : "Start Mining")
                                .font(.headline)
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .padding()
                                .background(isMining ? Color.red : Color.green)
                                .cornerRadius(12)
                        }
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(16)
                    
                    // Mining Statistics
                    if isMining {
                        VStack(spacing: 16) {
                            Text("Mining Statistics")
                                .font(.headline)
                            
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Hashrate")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Text("\(hashrate, specifier: "%.2f") H/s")
                                        .font(.subheadline.bold())
                                        .fontDesign(.monospaced)
                                }
                                
                                Spacer()
                                
                                VStack(alignment: .trailing, spacing: 4) {
                                    Text("Blocks Found")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Text("\(blocksFound)")
                                        .font(.subheadline.bold())
                                        .fontDesign(.monospaced)
                                }
                            }
                            
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Total Earnings")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Text("\(earnings, specifier: "%.6f") WEPO")
                                        .font(.subheadline.bold())
                                        .fontDesign(.monospaced)
                                        .foregroundColor(.green)
                                }
                                
                                Spacer()
                                
                                VStack(alignment: .trailing, spacing: 4) {
                                    Text("Est. Daily")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Text("\(hashrate * 0.001, specifier: "%.6f") WEPO")
                                        .font(.subheadline.bold())
                                        .fontDesign(.monospaced)
                                        .foregroundColor(.blue)
                                }
                            }
                        }
                        .padding()
                        .background(Color(.systemGray6))
                        .cornerRadius(12)
                    }
                    
                    // Mining Information
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Text("Mining Information")
                                .font(.headline)
                            
                            Spacer()
                            
                            Button(action: {
                                showingMiningInfo.toggle()
                            }) {
                                Image(systemName: showingMiningInfo ? "chevron.up" : "chevron.down")
                                    .foregroundColor(.blue)
                            }
                        }
                        
                        if showingMiningInfo {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Mobile Mining Details:")
                                    .font(.subheadline.bold())
                                
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("• Optimized for mobile devices")
                                        .font(.caption)
                                    Text("• Low battery consumption")
                                        .font(.caption)
                                    Text("• Rewards based on contribution")
                                        .font(.caption)
                                    Text("• Network security participation")
                                        .font(.caption)
                                }
                                .foregroundColor(.secondary)
                                .padding(.leading, 8)
                                
                                Text("Note: Mining runs in background when app is active. Performance may vary based on device capabilities.")
                                    .font(.caption)
                                    .foregroundColor(.orange)
                                    .padding(.top, 8)
                            }
                        }
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    
                    // Mining Rewards Info
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Reward Structure")
                            .font(.headline)
                        
                        VStack(spacing: 8) {
                            HStack {
                                Text("Block Reward:")
                                    .font(.subheadline)
                                Spacer()
                                Text("50 WEPO")
                                    .font(.subheadline.bold())
                                    .foregroundColor(.green)
                            }
                            
                            HStack {
                                Text("Miner Share:")
                                    .font(.subheadline)
                                Spacer()
                                Text("25%")
                                    .font(.subheadline.bold())
                                    .foregroundColor(.blue)
                            }
                            
                            HStack {
                                Text("Network Fee:")
                                    .font(.subheadline)
                                Spacer()
                                Text("0 WEPO")
                                    .font(.subheadline.bold())
                                    .foregroundColor(.green)
                            }
                        }
                        .padding(.vertical, 8)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                }
                .padding()
            }
            .navigationTitle("Mining")
            .onAppear {
                refreshMiningStatus()
            }
        }
    }
    
    private func toggleMining() {
        isMining.toggle()
        
        if isMining {
            startMining()
        } else {
            stopMining()
        }
    }
    
    private func startMining() {
        // Simulate mining activity
        hashrate = Double.random(in: 10...50)
        
        // Start periodic updates
        Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { timer in
            if !isMining {
                timer.invalidate()
                return
            }
            
            // Update mining stats
            hashrate = Double.random(in: hashrate * 0.9...hashrate * 1.1)
            
            // Occasionally find a block
            if Int.random(in: 1...100) == 1 {
                blocksFound += 1
                earnings += 12.5 // 25% of 50 WEPO block reward
            }
        }
    }
    
    private func stopMining() {
        hashrate = 0.0
    }
    
    private func refreshMiningStatus() {
        // In a real app, this would query the backend
        // For now, simulate some existing mining data
        earnings = Double.random(in: 0...100)
        blocksFound = Int(earnings / 12.5)
    }
}

#Preview {
    MiningView()
        .environmentObject(WalletManager())
}