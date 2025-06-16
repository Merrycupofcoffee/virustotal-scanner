# Adding Dependencies
import requests
import base64

# Function to get API Key from user
def get_api_key():
    return input("Please enter your VirusTotal API Key: ").strip()

# Function to get User Input
def user_input():
    return input("🧪 Please enter a hash, URL, or IP address to check: ").strip()

