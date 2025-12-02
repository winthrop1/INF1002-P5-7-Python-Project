"""
Vercel serverless entrypoint for the phishing detection Flask application.

This file serves as the entry point for Vercel deployments. It imports the Flask app
from the parent directory and exports it for Vercel's Python runtime.

For local development, continue using: python website.py
For Vercel deployment, this file is automatically detected and used.
"""

import sys
import os

# Add parent directory to Python path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the Flask app from website.py
from website import app

# Export app for Vercel (this is what Vercel looks for)
# The variable name MUST be 'app' for Vercel to detect it
app = app

# This allows testing the serverless function locally if needed
if __name__ == "__main__":
    app.run()
