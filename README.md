# README.md for Wazuh Alert Integration System

## Overview
This system integrates Wazuh alerts with TheHive and MISP to manage and correlate security alerts effectively. It is designed to be modular, allowing for easy adaptation to various security environments. The integration facilitates the automation of alert processing, searching for hash matches in MISP, and case creation in TheHive based on these matches.

## Key Components
- `config.py`: Manages configuration settings and environment variables.
- `main.py`: Initializes and runs the Flask application.
- `misp.py`: Handles interactions with MISP including searching for hash values.
- `thehive.py`: Manages alert creation and case processing in TheHive.
- `routes.py`: Configures Flask routes to handle incoming webhook requests.
- `utils.py`: Provides utilities for data extraction and hash data parsing.

## Installation

### Requirements
Python 3.8 or higher is recommended. Install all necessary Python packages by running:
```bash
pip install -r requirements.txt
```

### Environment Setup
You must configure the environment variables before running the application. Create a `.env` file in the root directory and include the following variables:
```
THEHIVE_URL=http://example.com/thehive
THEHIVE_KEY=YourTheHiveAPIKey
MISP_URL=http://example.com/misp
MISP_KEY=YourMISPAPIKey
MISP_VERIFYCERT=True
```

- `THEHIVE_URL`: URL of TheHive instance.
- `THEHIVE_KEY`: API key for TheHive.
- `MISP_URL`: URL of the MISP instance.
- `MISP_KEY`: API key for MISP.
- `MISP_VERIFYCERT`: Set to `False` to disable SSL certificate verification if needed.

### Running the Application
To start the Flask server, navigate to the project directory and run:
```bash
python main.py
```
The server will start in debug mode and listen for incoming webhook requests.

## Usage
Send JSON payloads from Wazuh to the `/webhook` endpoint configured in `routes.py`. The system will process these alerts, search for hash matches in MISP, and automatically create alerts and cases in TheHive.

## Modularity and Configuration
This application is designed to be highly modular. Future configurations can be made to adapt to different types of data inputs and to refine the data that triggers alerts or cases.

## Future Plans (TODO)
- **Configuration Expansion**: Move hardcoded lists and values to a configuration file or database for easier management.
  - **Files to Update**:
    - `thehive.py`: Modify excluded keys in `generate_artifacts` and adjust the artifact creation logic.
    - `utils.py`: Update hash types and parsing logic in `parse_hash_data` to accommodate additional or different hash types.
  - **Lines to Adjust**:
    - Lines involving `exclude_keys` in `thehive.py`.
    - Hash parsing logic in `utils.py`, specifically in the `parse_hash_data` function.

- **Enhancing Flexibility**:
  - Abstract more functionality into configurable modules or external configuration settings.
  - Allow for dynamic adjustment of logging levels and more detailed error handling strategies.

Contributors can refer to these plans for enhancing the system's functionality and customizing it to fit specific organizational needs. Contributions to extend compatibility, improve error handling, and increase the configurability of the system are welcome.
