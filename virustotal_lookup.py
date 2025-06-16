# Adding Dependencies
import requests
import base64

# Function to get API Key from user
def get_api_key():
    return input("Please enter your VirusTotal API Key: ").strip()

# Function to get User Input
def user_input():
    return input("🧪 Please enter a hash, URL, or IP address to check: ").strip()

# Function to get User Input and validate what type of input it is
def detect_input_type(value):
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
        return "hash"
    elif "." in value and all(c.isdigit() or c == '.' for c in value):
        return "ip"
    elif value.startswith("http://") or value.startswith("https://"):
        return "url"
    else:
        return "unknown"

# Function to concatenate the user input on to the url for virus total
def format_url(input_value, input_type):
    if input_type == "hash":
        return f"https://www.virustotal.com/api/v3/files/{input_value}"
    elif input_type == "ip":
        return f"https://www.virustotal.com/api/v3/ip_addresses/{input_value}"
    elif input_type == "url":
        url_id = base64.urlsafe_b64encode(input_value.encode()).decode().strip("=")
        return f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        return None

# Funtion to display results from the API response    
def display_results(response_json):
    stats = response_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    print("\nAnalysis Results:")
    for key, val in stats.items():
        print(f"{key.capitalize():<12}: {val}")

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        print("\nVerdict: MALICIOUS")
    elif suspicious > 0:
        print("\nVerdict: SUSPICIOUS")
    else:
        print("\nVerdict: CLEAN")