import SwiftUI

struct ContentView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var showingWalletSetup = false
    
    var body: some View {
        NavigationView {
            Group {
                if walletManager.hasWallet {
                    DashboardView()
                } else {
                    WelcomeView()
                }
            }
        }
        .onAppear {
            walletManager.loadWallet()
        }
        .sheet(isPresented: $showingWalletSetup) {
            WalletSetupView()
        }
    }
}

struct WelcomeView: View {
    @EnvironmentObject var walletManager: WalletManager
    @State private var showingWalletSetup = false
    
    var body: some View {
        VStack(spacing: 30) {
            Spacer()
            
            // WEPO Logo Placeholder
            Circle()
                .fill(Color.blue.gradient)
                .frame(width: 120, height: 120)
                .overlay(
                    Text("WEPO")
                        .font(.title.bold())
                        .foregroundColor(.white)
                )
            
            VStack(spacing: 16) {
                Text("Welcome to WEPO Wallet")
                    .font(.largeTitle.bold())
                    .multilineTextAlignment(.center)
                
                Text("Your gateway to decentralized finance with privacy-focused features and Bitcoin integration")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            
            Spacer()
            
            VStack(spacing: 16) {
                Button(action: {
                    showingWalletSetup = true
                }) {
                    Text("Create New Wallet")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .cornerRadius(12)
                }
                
                Button(action: {
                    showingWalletSetup = true
                }) {
                    Text("Import Existing Wallet")
                        .font(.headline)
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(12)
                }
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 50)
        }
        .sheet(isPresented: $showingWalletSetup) {
            WalletSetupView()
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(WalletManager())
}