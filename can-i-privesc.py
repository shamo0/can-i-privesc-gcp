import argparse
import requests
import tqdm
import re
from bs4 import BeautifulSoup
from google.oauth2 import service_account
import google.oauth2.credentials
import googleapiclient.discovery
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
# privesc-detector.py
from modules import check_privesc
from colorama import Fore, Style, init

init(autoreset=True)

def download_gcp_permissions():

    base_ref_page = requests.get("https://cloud.google.com/iam/docs/permissions-reference").text
    results = re.findall('<td id="([^"]+)"', base_ref_page)
    
    return results

def check_permissions(perms, service, project, folder, org, verbose):
    """Test if the user has the indicated permissions"""

    if project:
        req = service.projects().testIamPermissions(
            resource="projects/"+project,
            body={"permissions": perms},
        )

    elif folder:
        req = service.folders().testIamPermissions(
            resource="folders/"+folder,
            body={"permissions": perms},
        )

    elif org:
        req = service.organizations().testIamPermissions(
            resource="organizations/" +org,
            body={"permissions": perms},
        )

    have_perms = []

    try:
        returnedPermissions = req.execute()
        have_perms = returnedPermissions.get("permissions", [])
    except googleapiclient.errors.HttpError as e: 
        if "Cloud Resource Manager API has not been used" in str(e):
            print(str(e) + "\n Try to enable the service running: gcloud services enable cloudresourcemanager.googleapis.com")
            exit(1)

        for perm in perms:
            if " "+perm+" " in str(e): 
                perms.remove(perm)
                return check_permissions(perms, service, project, folder, org, verbose)
        
    except Exception as e:
        print("Error:")
        print(e)
    
    if have_perms and verbose:
        print(f"Found: {have_perms}")
    
    return have_perms


def divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i + n]
 

def main():
    parser = argparse.ArgumentParser(description='Check your permissions over an specific GCP project, folder or organization.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--project', help='Name of the project to use (e.g. digital-bonfire-186309)')
    group.add_argument('-f', '--folder', help='ID of the folder to use (e.g. 433637338589)')
    group.add_argument('-o', '--organization', help='ID of the organization to use (e.g. 433637338589)')
    parser.add_argument('-v','--verbose', help='Print the found permissions as they are found', action='store_true')
    parser.add_argument('-T','--threads', help='Number of threads to use, be careful with rate limits. Default is 3.', default=3, type=int)
    parser.add_argument('-s','--services', help='Comma separated list of GCP service by its api names to check only (e.g. filtering top 10 services: -s iam.,compute.,storage.,container.,bigquery.,cloudfunctions.,pubsub.,sqladmin.,cloudkms.,secretmanager.). Default is all services.', default='', type=str)
    parser.add_argument('-S','--size', help='Size of the chunks to divide all the services into. Default is 50.)', default=50)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c','--credentials', help='Path to credentials.json')
    group.add_argument('-t','--token', help='Raw access token')
    args = vars(parser.parse_args())

    project = args['project']
    folder = args['folder']
    org = args['organization']

    verbose = args['verbose']
    n_threads = int(args['threads'])
    services_grep = [s.strip() for s in args['services'].split(',')] if args['services'] else []
    if args.get('token'):
        access_token = args['token']
        credentials = google.oauth2.credentials.Credentials(access_token.rstrip())
    else:
        credentials_path = args['credentials']

        credentials = service_account.Credentials.from_service_account_file(
            credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

    list_perms = list(set(download_gcp_permissions()))
    if list_perms is None or len(list_perms) == 0:
        print("Couldn't download the permissions")
        return
    list_perms.sort()

    print(f"Downloaded {len(list_perms)} GCP permissions")
    
    if len(services_grep)>0:

        list_perms = [perm for perm in list_perms for grep_perm in services_grep if grep_perm.lower() in perm.lower()]
        print(f"Filtered to {len(list_perms)} GCP permissions")


    divided_list_perms = list(divide_chunks(list_perms, 20))
    have_perms = []
    have_perms_lock = Lock()  # Lock for thread-safe operations on have_perms

    def thread_function(subperms):

        service = googleapiclient.discovery.build(
            "cloudresourcemanager", "v3", credentials=credentials
        )

        perms = check_permissions(subperms, service, project, folder, org, verbose)
        with have_perms_lock:  
            have_perms.extend(perms)
    
    def handle_future(future, progress):
        try:
            result = future.result()  
 
        except Exception as exc:
            print(f"Thread resulted in an exception: {exc}")
        finally:
            progress.update(1)  

    with concurrent.futures.ThreadPoolExecutor(max_workers=n_threads) as executor:
        with tqdm.tqdm(total=len(divided_list_perms)) as progress:
            futures = [executor.submit(thread_function, subperms) for subperms in divided_list_perms]
            
            for future in concurrent.futures.as_completed(futures):
                handle_future(future, progress)

    # Print user's permissions
    print(f"{Fore.CYAN}[INFO] Your Effective Permissions:{Style.RESET_ALL}\n")
    print(Fore.LIGHTWHITE_EX + '\n'.join(f"  🔑 {perm}" for perm in have_perms) + Style.RESET_ALL)
    print("\n")

    # Check privilege escalation
    detected_privesc = check_privesc.check_privesc(have_perms)

    if detected_privesc:
        print(f"\n{Fore.RED}[!] Detected Privilege Escalation Paths:{Style.RESET_ALL}\n")
        for attack_name, details in detected_privesc.items():
            print(f"{Fore.YELLOW}⚡ {attack_name}:{Style.RESET_ALL}")
            print(Fore.LIGHTWHITE_EX + "  🔎 Required Permissions:" + Style.RESET_ALL)
            for perm in details["permissions"]:
                print(Fore.LIGHTYELLOW_EX + f"    - {perm}" + Style.RESET_ALL)
            if details["link"]:
                print(Fore.LIGHTBLUE_EX + f"  🔗 More Info: {details['link']}" + Style.RESET_ALL)
            print()  # Add a newline for readability
    else:
        print(f"\n{Fore.GREEN}✔ No privilege escalation detected.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
