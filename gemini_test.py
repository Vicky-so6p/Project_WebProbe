import requests
from bs4 import BeautifulSoup
import google.generativeai as genai
import os
import json

# Initialize Gemini model
GOOGLE_API_KEY = os.environ.get("PLACE_API_KEY_HERE")
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel(model_name='gemini-2.0-flash') # Changed model name

def fetch_url_content(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    try:
        print(f"*** Gemini Test - Fetching content for: {url} ***")  # Debugging
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        text_content = soup.get_text(separator='\n', strip=True)
        return text_content[:5000] # Limit content for analysis
    except requests.exceptions.RequestException as e:
        error_message = f"Error fetching URL: {e}"
        print(f"*** Gemini Test - Error fetching {url}: {error_message} ***") # Debugging
        return error_message

def analyze_url_purpose(url):
    content = fetch_url_content(url)
    if "Error fetching URL" in content:
        return content

    prompt = f"Describe the primary function and category of the following website. Provide the use case of the website and give some clarifications on the legitimity of the website in a brief. If the website is not that legitimate, provide some other legit alternatives (only if the website is suspicious). If its not suspicious, and found to be legitimate, say thet clearly and suggest by addressing even though it is legitimate, here are some alternatives which you might find helpful(something likethat). And avoid using unneccessary spaces while formatting.: {url}"  # Improved prompt

    try:
        print(f"*** Gemini Test - Analyzing purpose for: {url} ***")  # Debugging
        response = model.generate_content(prompt)
        purpose = response.text.strip()
        print(f"*** Gemini Test - Purpose found: {purpose} ***")  # Debugging
        return purpose
    except Exception as e:
        error_message = f"Error analyzing content with Gemini: {e}"
        print(f"*** Gemini Test - Gemini Analysis Error: {error_message} ***") # Debugging
        return error_message
    
def analyze_scan_report(scan_data, query):
    prompt = f"""You are a helpful chatbot assisting a user with understanding a URL security scan report and also about some general query regarding the url involved. The query might either be regarding the scan or a general clarification question, be aware of what the user asks and provide the answer for it. The user might ask about something that is not related to this scan report, you must address it even if it is not based on this scan. Format your response to be clear, concise, and easy to read. Your response is directly displayed in a seperate window do provide the response in a formatted way it feels readable. Most importantly, if the response involved searches on internet do not mention that internet searching part. If the query is regarding the scan report, refer the report data.For general questions, try to minimise the use of scan report. Understand what the user is trying to ask and provide response in a conversational way.
    The report data is as follows: {json.dumps(scan_data)}. 
    Answer the user's question: '{query}'."""
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Error analyzing scan report with Gemini: {e}"

if __name__ == '__main__':
    test_urls = [
        "https://www.amazon.com/",
        "https://www.bbc.com/news",
        "https://openai.com/blog/",
        "https://www.nasa.gov/",
        "https://malware.wicar.org/data/iFrame.html"
        "https://www.elamigos-games.net/"
    ]
    for url in test_urls:
        purpose = analyze_url_purpose(url)
        print(f"URL: {url}\nPurpose: {purpose}\n---")
