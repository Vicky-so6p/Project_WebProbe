import requests
import time

class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {"x-apikey": api_key}

    def scan_url(self, url):
        scan_endpoint = f"{self.base_url}urls"
        try:
            payload = {"url": url}
            response = requests.post(scan_endpoint, headers=self.headers, data=payload)
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]
            time.sleep(15)
            analysis_endpoint = f"{self.base_url}analyses/{analysis_id}"
            analysis_response = requests.get(analysis_endpoint, headers=self.headers)
            analysis_response.raise_for_status()
            return analysis_response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error scanning {url}: {e}")
            return None