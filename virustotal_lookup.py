# Adding Dependencies
import requests
import base64

# Function to get API Key from user
def get_api_key():
    return input("Please enter your VirusTotal API Key: ").strip()