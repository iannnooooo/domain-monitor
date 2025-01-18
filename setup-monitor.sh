#!/bin/bash

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    echo "GitHub CLI (gh) is required. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install gh
    else
        # For Ubuntu/Debian
        curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
        sudo apt update
        sudo apt install gh
    fi
fi

# Login to GitHub CLI if not already
gh auth status || gh auth login

# Initialize git
git init

# Create GitHub repo and push
gh repo create domain-monitor --public --push --source=.

echo "Setup complete! Your domain monitor is now running."
echo "Check the Actions tab in your GitHub repo for results."
