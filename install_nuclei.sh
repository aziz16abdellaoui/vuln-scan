#!/bin/bash

# Script to install Nuclei for vulnerability scanning

echo "🔧 Installing Nuclei..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Installing Go..."
    
    # Install Go
    wget https://go.dev/dl/go1.21.3.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.3.linux-amd64.tar.gz
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
    export PATH=$PATH:/usr/local/go/bin
    
    rm go1.21.3.linux-amd64.tar.gz
    echo "✅ Go installed successfully"
else
    echo "✅ Go is already installed"
fi

# Install Nuclei
echo "🔧 Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add ~/go/bin to PATH if not already there
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
    export PATH=$PATH:$HOME/go/bin
fi

# Update Nuclei templates
echo "📡 Updating Nuclei templates..."
nuclei -update-templates

echo "✅ Nuclei installation complete!"
echo "🎯 Test with: nuclei -u https://example.com"
echo "📚 Templates location: ~/nuclei-templates/"

# Verify installation
if command -v nuclei &> /dev/null; then
    echo "✅ Nuclei is ready to use!"
    nuclei -version
else
    echo "❌ Nuclei installation failed. Please check the logs above."
fi
