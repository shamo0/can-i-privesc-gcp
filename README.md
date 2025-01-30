# Can-I-Privesc-GCP - GCP Privilege Escalation Detection Tool

## Description

Can-I-Privesc-GCP is a tool designed to identify effective permissions in a Google Cloud Platform (GCP) environment and analyze them for potential privilege escalation risks. The tool retrieves permissions granted to a user, service account, or organization and checks for known privilege escalation attack paths.

The project is based on two core functionalities:

- Brute-force testing for GCP permissions – This method attempts to check all possible permissions available to the user.
- Privilege escalation detection – After retrieving the user's permissions, the script analyzes them to determine if any privilege escalation paths exist, referencing known attack vectors.

## Features

- Retrieves all effective permissions granted to the user.
- Analyzes permissions for known privilege escalation paths.
- Provides detailed information on detected privilege escalation risks.
- Includes direct links to HackTricks documentation for further research on privilege escalation techniques.

## Usage

The tool requires GCP credentials and can be run against a project, folder, or organization to check available permissions and privilege escalation possibilities.

### Running the Script

1. Install the dependencies

```pip install -r requirements.txt```

2. Run the script

```python3 can-i-privesc-gcp.py --project <PROJECT_ID>```

3. The tool will enumerate permissions and check for privilege escalation paths automatically

## Credits

The GCP permission brute-force enumeration part of this script is originally developed by Carlospolop, the creator of HackTricks. This tool extends and enhances his work by adding privilege escalation detection and a structured analysis of permissions.

## Contributing

Contributions are welcome! If you have new privilege escalation techniques or improvements, feel free to submit a pull request or open an issue.

## Disclaimer 

This tool is intended for security professionals, auditors, and penetration testers with proper authorization. Misuse of this tool may result in legal consequences. The authors are not responsible for any misuse or damage caused by this tool.