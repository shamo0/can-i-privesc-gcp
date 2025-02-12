# GCP Privilege Escalation Detection

![image](https://github.com/user-attachments/assets/c3c58751-dbd0-4553-85f6-771157a75b12)

## Description

Can-I-Privesc-GCP is a tool designed to identify effective permissions in a Google Cloud Platform (GCP) environment and analyze them for potential privilege escalation risks. The tool retrieves permissions granted to a user, service account, or organization and checks for known privilege escalation attack paths.



## Features

- Retrieves all effective permissions granted to the user.
- Analyzes permissions for known privilege escalation paths.
- Provides detailed information on detected privilege escalation risks.
- Includes direct links to HackTricks documentation for further research on privilege escalation techniques.

## Usage

The tool requires GCP credentials and can be run against a project, folder, or organization to check available permissions and privilege escalation possibilities. Check ```python3 can-i-privesc-gcp.py -h``` for detailed options

### Running the Script

```bash
git clone https://github.com/shamo0/can-i-privesc-gcp.git
cd can-i-privesc-gcp
pip install -r requirements.txt
python3 can-i-privesc-gcp.py --project <PROJECT_ID> -t $(gcloud auth print-access-token)
```


## Credits

The GCP permission [brute-force enumeration](https://github.com/carlospolop/bf_my_gcp_permissions) part of this script is originally developed by Carlos Polop, the creator of HackTricks. This tool extends and enhances his work by adding privilege escalation detection and a structured analysis of permissions.

## ToDo

- Add Post Exploitation path detection

## Contributing

Contributions are welcome! If you have new privilege escalation techniques or improvements, feel free to submit a pull request or open an issue.

## Disclaimer 

This tool is intended for security professionals, auditors, and penetration testers with proper authorization. Misuse of this tool may result in legal consequences. The authors are not responsible for any misuse or damage caused by this tool.
