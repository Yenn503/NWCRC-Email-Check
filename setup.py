#!/usr/bin/env python3
"""
Setup script for Email Breach Scanner
"""

import os
import sys
import subprocess

def install_requirements():
    """Install required packages"""
    print("Installing required packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def create_directories():
    """Create necessary directories"""
    directories = ["exports", "logs", "static/uploads"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

def setup_environment():
    """Setup environment file"""
    env_file = ".env"
    if not os.path.exists(env_file):
        with open(env_file, "w") as f:
            f.write("# Email Breach Scanner Configuration\n")
            f.write("HIBP_API_KEY=your_api_key_here\n")
            f.write("SECRET_KEY=your_secret_key_here\n")
            f.write("DEBUG=True\n")
        print(f"Created {env_file} - Please update with your API keys")
    else:
        print(f"{env_file} already exists")

def main():
    print("Setting up Email Breach Scanner...")
    
    try:
        install_requirements()
        create_directories()
        setup_environment()
        
        print("\n" + "="*50)
        print("Setup completed successfully!")
        print("="*50)
        print("\nNext steps:")
        print("1. Get your API key from https://haveibeenpwned.com/API/Key")
        print("2. Update the HIBP_API_KEY in .env file")
        print("3. Generate a secret key and update SECRET_KEY in .env")
        print("4. Run: python app.py")
        print("5. Open http://localhost:5000 in your browser")
        print("\nFor help, see README.md")
        
    except Exception as e:
        print(f"Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
