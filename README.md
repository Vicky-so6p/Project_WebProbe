# Project_WebProbe

A web probing tool enhanced by generative AI.

## Overview

Project\_WebProbe is designed to investigate and analyze websites, leveraging the power of generative AI to provide insightful information beyond traditional web probing techniques. This tool can be used for security analysis, content understanding, identifying potential threats, and generating novel insights about the target website.

## Features

* **Intelligent Web Content Analysis via Generative AI:** Goes beyond traditional scraping by employing advanced generative AI models to deeply analyze website content, extracting key insights, summarizing complex information, and identifying underlying themes with a human-like understanding.
* **Malicious Content and Threat Detection:** Leverages generative AI to intelligently scan website content, code, and behavior for potential indicators of malicious activity, phishing attempts, malware distribution, and other security threats, providing context-aware risk assessments.
* **Interactive AI Scan Chat:** Offers a unique conversational interface powered by generative AI, allowing users to ask natural language questions about the scanned website and receive detailed, context-aware answers and explanations about its content, technologies, and potential security posture.
* **Comprehensive Website Metadata and Details Scanning:** Automatically extracts and presents crucial website metadata, including HTTP headers, server information, DNS records, SSL/TLS certificate details, linked domains, and other technical information relevant for analysis.
* **Detailed Scan Report Generation:** Provides users with comprehensive reports summarizing the findings of the web probe, including AI-driven analysis, identified technologies, potential threats, extracted metadata, and other relevant details in a clear and organized format.

## Getting Started

This section will guide you on how to use Project\_WebProbe locally.

### Prerequisites

* Python 3.x
* pip (Python package installer)
* Potentially other dependencies as the project develops (e.g., specific AI libraries). Check the `requirements.txt` file (if it exists) for a complete list.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Vicky-so6p/Project_WebProbe.git](https://github.com/Vicky-so6p/Project_WebProbe.git)
    cd Project_WebProbe
    ```

2.  **Install dependencies (if applicable):**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: If you don't have a `requirements.txt` file yet, this step can be skipped for now.)*

### Usage (Local Development)

1.  **Open the project folder in your preferred text editor** (e.g., VS Code) to view the code and any configuration files.

2.  **Configure the Gemini API Key (Primary Method: Directly in `gemini_test.py`):**
    * Navigate to the `gemini_test.py` file within the project.
    * Open this file and locate the line:
      ```python
      GOOGLE_API_KEY = os.environ.get("PLACE_API_KEY_HERE")
      ```
    * **Replace `"PLACE_API_KEY_HERE"` with your actual API key** for the Gemini Model 2.0 Flash. You will need to obtain this key from the Google Cloud AI Platform or the appropriate Google AI service. Ensure you keep the quotation marks around your key. The line should look similar to:
      ```python
      GOOGLE_API_KEY = os.environ.get("YOUR_ACTUAL_API_KEY")
      ```

3.  **Configure the Gemini API Key (Secondary Method: Environment Variable - If Issues Occur):**
    * If you encounter issues connecting to the Gemini API using the direct method, you can try setting the API key as an environment variable.
    * In your terminal (before running the application), set the environment variable:
        * **Windows (PowerShell):**
            ```powershell
            $env:GOOGLE_API_KEY = "YOUR_ACTUAL_API_KEY"
            ```
        * **Linux/macOS (Bash/Zsh):**
            ```bash
            export GOOGLE_API_KEY="YOUR_ACTUAL_API_KEY"
            ```
        * **Replace `"YOUR_ACTUAL_API_KEY"` with your actual Gemini Model 2.0 Flash API key.**

4.  **Navigate to the WebProbe folder:** Assuming the main application files are located within a subdirectory named `WebProbe`, navigate into it:
    ```bash
    cd WebProbe
    ```

5.  **Run the web application:** Execute the main Python script (`app.py`) to start the local web server:
    ```bash
    python app.py
    ```

6.  **Access the website:** Once the application starts, it should be accessible in your web browser at a local host address (typically `http://localhost:5000` or a similar address). The exact address will usually be displayed in your terminal output when you run `python app.py`.

#### Important Notes

* **Gemini API Key Configuration:** **The primary way to provide your Gemini Model 2.0 Flash API key is by directly replacing `"PLACE_API_KEY_HERE"` with your key in the `gemini_test.py` file. If you experience connection issues, you can try setting the `GOOGLE_API_KEY` environment variable as an alternative.**
* **Environment Variable Precedence:** If you set the `GOOGLE_API_KEY` environment variable, the application might prioritize this over the key directly written in the `gemini_test.py` file (depending on how the code is implemented).
* **API Connection Issues and Temporary Environment:**
    * If you continue to encounter issues connecting to the Gemini API, ensure your API key is valid and that you have the necessary network connectivity.
    * For temporary testing or if you face persistent API connection problems, you might consider setting up a **local mock environment** or using a simplified version of the AI functionality that doesn't rely on the external API. Refer to the comments or documentation within your AI-related scripts for any existing mock implementations or instructions.
* **Check the terminal output:** Pay close attention to the terminal after running `python app.py`. It might display the specific local host address and port where the website is running.
* **Dependencies:** Ensure that all the necessary libraries are correctly listed in your `requirements.txt` file. If you encounter errors during the `pip install` step, double-check the contents of this file.
* **Potential Configuration:** Depending on your application, you might need to configure certain settings (e.g., database connections) before running it. Look for configuration files (like `.env` or `config.ini`) in your project and follow any instructions provided in them or in other documentation.
