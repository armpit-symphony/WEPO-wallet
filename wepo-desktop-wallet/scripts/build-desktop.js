const fs = require('fs-extra');
const path = require('path');

async function buildFrontend() {
  console.log('🔨 Building frontend...');
  
  const { spawn } = require('child_process');
  
  return new Promise((resolve, reject) => {
    const buildProcess = spawn('npm', ['run', 'build'], {
      cwd: path.join(__dirname, '../src/frontend'),
      stdio: 'inherit'
    });
    
    buildProcess.on('close', (code) => {
      if (code === 0) {
        console.log('✅ Frontend build complete');
        resolve();
      } else {
        console.error('❌ Frontend build failed');
        reject(new Error(`Build failed with code ${code}`));
      }
    });
  });
}

async function copyAssets() {
  console.log('📁 Copying assets...');
  
  // Copy built frontend to resources
  const frontendBuild = path.join(__dirname, '../src/frontend/build');
  const resourcesDir = path.join(__dirname, '../resources/frontend');
  
  await fs.ensureDir(resourcesDir);
  await fs.copy(frontendBuild, resourcesDir);
  
  console.log('✅ Assets copied');
}

async function main() {
  try {
    await buildFrontend();
    await copyAssets();
    console.log('🎉 Build process complete!');
  } catch (error) {
    console.error('❌ Build failed:', error.message);
    process.exit(1);
  }
}

main();