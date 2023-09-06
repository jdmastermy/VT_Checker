import requests

API_KEY = "PLACE YOUR VT API KEY"
BASE_URL = "https://www.virustotal.com/api/v3/"

HEADERS = {
    "x-apikey": API_KEY
}

def fetch_data(endpoint, identifier):
    url = f"{BASE_URL}{endpoint}/{identifier}"
    response = requests.get(url, headers=HEADERS)

    if response.status_code != 200:
        return None
    return response.json()

def check_ip_reputation(ip):
    data = fetch_data("ip_addresses", ip)
    if not data:
        return {"ip": ip, "reputation": "Error", "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}/detection"}

    malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    reputation = "Malicious" if malicious_count > 0 else "Clean"
    
    return {
        "ip": ip, 
        "reputation": reputation, 
        "vt_link": f"https://www.virustotal.com/gui/ip-address/{ip}/detection"
    }

def check_url_reputation(url):
    data = fetch_data("urls", url)
    if not data:
        return {"url": url, "reputation": "Error", "vt_link": f"https://www.virustotal.com/gui/url/{url}/detection"}

    malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    reputation = "Malicious" if malicious_count > 0 else "Clean"
    
    return {
        "url": url, 
        "reputation": reputation, 
        "vt_link": f"https://www.virustotal.com/gui/url/{url}/detection"
    }

def check_hash_reputation(hash_sum, hash_type):
    data = fetch_data("files", hash_sum)
    if not data:
        return {
            "hash": hash_sum, 
            "hash_type": hash_type, 
            "malicious_detections": "Error", 
            "vt_link": f"https://www.virustotal.com/gui/file/{hash_sum}/detection"
        }

    malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    
    return {
        "hash": hash_sum, 
        "hash_type": hash_type, 
        "malicious_detections": malicious_count, 
        "vt_link": f"https://www.virustotal.com/gui/file/{hash_sum}/detection"
    }
