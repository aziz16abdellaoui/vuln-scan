#!/usr/bin/env python3
"""
Entry point for Heroku deployment.
Imports the Flask app from app_modular.py
"""

from app_modular import app

if __name__ == "__main__":
    app.run()
