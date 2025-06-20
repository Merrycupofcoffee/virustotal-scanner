# Adding Dependencies
import requests
import base64

# My VirusTotoal API Key: 9b098068923b3ce794f81b553e13c45f7914accfc08831278ce29b33ad24fe14

# Function to get API Key from user
def get_api_key():
    return input("Please enter your VirusTotal API Key: ").strip()

# Function to get User Input
def user_input():
    return input("Please enter a hash, URL, or IP address to check: ").strip()

# Function to get User Input and validate what type of input it is
def detect_input_type(value):

    hex_chars = "0123456789abcdefABCDEF"

    if len(value) == 32 and all(c in hex_chars for c in value):
        return "hash"  # MD5
    elif len(value) == 40 and all(c in hex_chars for c in value):
        return "hash"  # SHA1
    elif len(value) == 64 and all(c in hex_chars for c in value):
        return "hash"  # SHA256
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
    for key, value in stats.items():
        print(f"{key.capitalize():<12}: {value}")

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        print("\nVerdict: MALICIOUS")
    elif suspicious > 0:
        print("\nVerdict: SUSPICIOUS")
    else:
        print("\nVerdict: CLEAN")

# Funtion to query VirusTotal API
def query_virustotal(api_key, input_value, input_type):
    url = format_url(input_value, input_type)
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        display_results(response.json())
    elif response.status_code == 404:
        print("No results found for this input.")
    elif response.status_code == 401:
        print("Invalid API Key.")
    else:
        print(f"Error {response.status_code}: {response.text}")

# Main
def main():
    print("=== VirusTotal Scanner ===")
    api_key = get_api_key()

    while True:
        input_value = user_input()
        input_type = detect_input_type(input_value)

        if input_type == "unknown":
            print("Unable to detect input type (not a valid hash, IP, or URL).")
        else:
            query_virustotal(api_key, input_value, input_type)

        choice = input("\nPress 1 to scan another hash / IP / URL, or press Enter to exit: ").strip()
        if choice != "1":
            print("Goodbye!")
            break

if __name__ == "__main__":
    main()