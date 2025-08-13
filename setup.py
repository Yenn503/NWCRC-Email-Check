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
    directories = ["exports", "uploads"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

def setup_environment():
    """Point user to .env.example"""
    example_file = ".env.example"
    if os.path.exists(example_file):
        print("Use .env.example as a template: copy it to .env and fill values.")
    else:
        print("Create a .env file with HIBP_API_KEY, SECRET_KEY, FLASK_DEBUG, RATE_LIMIT_PER_MINUTE, CHECK_PASTES.")

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
        port = os.environ.get('PORT') or os.environ.get('APP_PORT') or '8000'
        print("4. Run: python app.py")
        print(f"5. Open http://localhost:{port} in your browser")
        print("\nFor help, see README.md")
        
    except Exception as e:
        print(f"Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
