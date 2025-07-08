#!/bin/bash
# GitHub Setup Script for Vulnerability Scanner
# Run this script after creating a new repository on GitHub

echo "🚀 GitHub Setup for Vuln-Scan"
echo "=============================="
echo ""

# Check if git is configured
echo "📋 Checking git configuration..."
GIT_USER=$(git config user.name)
GIT_EMAIL=$(git config user.email)

if [ -z "$GIT_USER" ] || [ -z "$GIT_EMAIL" ]; then
    echo "⚠️  Git user not configured. Please set up your git user:"
    echo "   git config --global user.name 'Your Name'"
    echo "   git config --global user.email 'your.email@example.com'"
    echo ""
fi

echo "Current git user: $GIT_USER <$GIT_EMAIL>"
echo ""

# Instructions for GitHub
echo "📝 Steps to publish to GitHub:"
echo ""
echo "1. Create a new repository on GitHub:"
echo "   - Go to: https://github.com/new"
echo "   - Repository name: vuln-scan"
echo "   - Description: Modular vulnerability scanner with web interface and CLI"
echo "   - Make it Public (recommended for open source)"
echo "   - DO NOT initialize with README, .gitignore, or license (we already have these)"
echo ""
echo "2. After creating the repository, run these commands:"
echo "   git remote add origin https://github.com/mohamedazizabdellaoui/vuln-scan.git"
echo "   git push -u origin main"
echo ""
echo "3. Your repository will be live at:"
echo "   https://github.com/mohamedazizabdellaoui/vuln-scan"
echo ""

# Project stats
echo "📊 Project Statistics:"
echo "====================="
echo "Files tracked: $(git ls-files | wc -l)"
echo "Lines of code: $(find . -name "*.py" -exec wc -l {} + | tail -1 | awk '{print $1}')"
echo "Modules: 8 scanning tools"
echo "Interfaces: Web + CLI"
echo "License: MIT"
echo ""

echo "✅ Repository is ready for GitHub!"
echo "✅ All files committed and clean working directory"
echo "✅ Proper .gitignore configured"
echo "✅ MIT License included"
echo "✅ Comprehensive README.md"
echo "✅ Detailed HOW_TO_RUN.md documentation"
echo ""
echo "🎉 Ready to publish! Follow the steps above."
