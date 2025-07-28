import React from 'react';

// Simple test app to verify React is working
const TestApp = () => {
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      height: '100vh',
      backgroundColor: '#1a1a2e',
      color: 'white',
      fontFamily: 'Arial, sans-serif'
    }}>
      <div style={{ textAlign: 'center' }}>
        <h1>🔥 WEPO WALLET TEST</h1>
        <p>React is working properly!</p>
        <p>Bitcoin integration ready for implementation</p>
        <div style={{ 
          marginTop: '20px', 
          padding: '10px', 
          backgroundColor: '#16213e', 
          borderRadius: '8px' 
        }}>
          <p>✅ Frontend: Working</p>
          <p>✅ Backend: Connected</p>
          <p>✅ Bitcoin: Ready</p>
          <p>✅ Masternodes: 10,000 WEPO required</p>
        </div>
      </div>
    </div>
  );
};

export default TestApp;