def check_privesc(perms_list):
    
    detected_privesc = {}
    perms_set = set(perms_list)  

    privesc_conditions = {
        "apikeys": [
            ({"apikeys.keys.create"}, "Create API Keys"),
            ({"apikeys.keys.getKeyString", "apikeys.keys.list"}, "List and Get all API keys"),
            ({"apikeys.keys.undelete", "apikeys.keys.list"}, "List and regenerate deleted API keys"),
        ],
        "appengine": [
            (
                {
                    "appengine.applications.get", "appengine.instances.get", "appengine.instances.list",
                    "appengine.operations.get", "appengine.operations.list", "appengine.services.get",
                    "appengine.services.list", "appengine.versions.create", "appengine.versions.get",
                    "appengine.versions.list", "cloudbuild.builds.get", "iam.serviceAccounts.actAs",
                    "resourcemanager.projects.get", "storage.objects.create", "storage.objects.list"
                },  "Deploy an App using gcloud cli"
                
            ),
            (
                {
                    "appengine.instances.enableDebug", "appengine.instances.get", "appengine.instances.list", 
                    "appengine.operations.get", "appengine.services.get", "appengine.services.list", 
                    "appengine.versions.get", "appengine.versions.list", "compute.projects.get"
                },  "Login via ssh in App Engine instances"
            ),
            (
                {
                    "appengine.applications.update", "appengine.operations.get"
                },  "Change the background Google used SA"
            ),
            (
                {
                    "appengine.versions.getFileContents", "appengine.versions.update"
                },  "Possible - changing the code inside the bucket"
            )
        ],
        "artifactregistry": [
            ({"artifactregistry.repositories.uploadArtifacts"}, "Upload new versions of the artifacts"),
            ({"artifactregistry.repositories.downloadArtifacts"}, "Download artifacts and search for sensitive information and vulnerabilities"),
            ({"artifactregistry.repositories.delete"}, "Delete artifacts from the registry, like docker images"),
            ({"artifactregistry.repositories.setIamPolicy"}, "Give yourself permissions over Artifact Registry repositories"),
            (
                {
                    "artifactregistry.tags.delete", "artifactregistry.versions.delete", "artifactregistry.packages.delete", 
                    "artifactregistry.repositories.get", "artifactregistry.tags.get", "artifactregistry.tags.list"
                },  "Delete artifacts from the registry, like docker images:"
            ),
        ],
        "batch": [
            ({"batch.jobs.create", "iam.serviceAccounts.actAs"}, "Create a batch job, get a reverse shell and exfiltrate the metadata token of the SA"),
        ],
        "bigquery": [
            ({"bigquery.datasets.setIamPolicy"}, "Give yourself further permissions over a BigQuery dataset"),
            ({"bigquery.datasets.update", "bigquery.datasets.get"}, "Update your access over a BigQuery dataset by modifying the ACLs"),
            ({"bigquery.tables.setIamPolicy"}, "Give yourself further permissions over a BigQuery table"),
            (
                {
                    "bigquery.rowAccessPolicies.update", "bigquery.rowAccessPolicies.setIamPolicy", "bigquery.tables.getData", "bigquery.jobs.create"
                },  "update a row policy"
            ),
        ],
        "clientauthconfig": [
            (
                {
                    "clientauthconfig.brands.list", "clientauthconfig.brands.create", "clientauthconfig.brands.get",
                    "clientauthconfig.clients.create", "clientauthconfig.clients.listWithSecrets", "clientauthconfig.clients.getWithSecret",
                    "clientauthconfig.clients.delete", "clientauthconfig.clients.update"
                },  "Create OAuth Brand and Client"
            ),
        ],
        "cloudbuild": [
            ({"cloudbuild.builds.update"}, "Update a cloud build (Potential)"),
            ({"cloudbuild.builds.create", "iam.serviceAccounts.actAs"}, "Submit a cloud build"),
            ({"cloudbuild.repositories.accessReadToken"}, "Read access token used to access the repository"),
            ({"cloudbuild.repositories.accessReadWriteToken"}, "Read and write access token used to access the repository"),
            ({"cloudbuild.connections.fetchLinkableRepositories"}, "Get the repos the connection has access to"),
        ],
        "cloudfunctions": [
            ({"cloudfunctions.functions.create", "cloudfunctions.functions.sourceCodeSet", "iam.serviceAccounts.actAs"}, "Create a new Cloud Function with arbitrary (malicious) code and assign it a Service Account"),
            ({"cloudfunctions.functions.update", "cloudfunctions.functions.sourceCodeSet", "iam.serviceAccounts.actAs"}, "Modify the code of a Function and even modify the service account attached"),
            ({"cloudfunctions.functions.sourceCodeSet"}, "Get a signed URL to be able to upload a file to a function bucket"),
            ({"cloudfunctions.functions.setIamPolicy", "iam.serviceAccounts.actAs"}, "Give yourself any of the .update or .create privileges to escalate"),
        ],
        "cloudscheduler": [
            ({"cloudscheduler.jobs.create", "iam.serviceAccounts.actAs", "cloudscheduler.locations.list"}, "Authenticate cron jobs as a specific Service Account"),
            ({"cloudscheduler.jobs.update" , "iam.serviceAccounts.actAs", "cloudscheduler.locations.list"}, "Update an already created scheduler "),
        ],
        "composer": [
            ({"composer.environments.create"}, "Attach any service account to the newly created composer environment"),
            ({"composer.environments.update"}, "Update composer environment, for example, modifying env variables"),
        ],
        "container": [
            ({"container.clusters.get"}, "Gather credentials for the Kubernetes cluster"),
            ({"container.roles.escalate"}, "Create or update Roles with more permissions"),
            ({"container.clusterRoles.escalate"}, "Create or update ClusterRoles with more permissions"),
            ({"container.roles.bind"}, "Create or update RoleBindings to give more permissions"),
            ({"container.clusterRoles.bind"}, "Create or update ClusterRoleBindings to give more permissions"),
            ({"container.secrets.get", "container.secrets.list"}, "Read the tokens of all the SAs of kubernetes"),
            ({"container.pods.exec"}, "Exec into pods"),
            ({"container.pods.portForward"}, "Access local services running in pods"),
            ({"container.serviceAccounts.createToken"}, "Generate tokens of the K8s Service Accounts"),
            ({"container.cronJobs.create"}, "Create or update a resource where you can define a pod"),
            ({"container.cronJobs.update"}, "Create or update a resource where you can define a pod"),
            ({"container.daemonSets.create"}, "Create or update a resource where you can define a pod"),
            ({"container.daemonSets.update"}, "Create or update a resource where you can define a pod"),
            ({"container.deployments.create"}, "Create or update a resource where you can define a pod"),
            ({"container.deployments.update"}, "Create or update a resource where you can define a pod"),
            ({"container.jobs.create"}, "Create or update a resource where you can define a pod"),
            ({"container.jobs.update"}, "Create or update a resource where you can define a pod"),
            ({"container.pods.create"}, "Create or update a resource where you can define a pod"),
            ({"container.pods.update"}, "Create or update a resource where you can define a pod"),
            ({"container.replicaSets.create"}, "Create or update a resource where you can define a pod"),
            ({"container.replicaSets.update"}, "Create or update a resource where you can define a pod"),
            ({"container.replicationControllers.create"}, "Create or update a resource where you can define a pod"),
            ({"container.replicationControllers.update"}, "Create or update a resource where you can define a pod"),
            ({"container.scheduledJobs.create"}, "Create or update a resource where you can define a pod"),
            ({"container.scheduledJobs.update"}, "Create or update a resource where you can define a pod"),            
            ({"container.statefulSets.create"}, "Create or update a resource where you can define a pod"),
            ({"container.statefulSets.update"}, "Create or update a resource where you can define a pod"),            
        ],
        "dataproc": [
            ({"dataproc.clusters.get", "dataproc.clusters.use", "dataproc.jobs.create", 
              "dataproc.jobs.get", "dataproc.jobs.list", "storage.objects.create", "storage.objects.get"
             }, 
               "Leak SA token from the metadata endpoint"),
        ],
        "deploymentmanager": [
            ({"deploymentmanager.deployments.create"}, "Launch new deployments of resources in GCP with arbitrary service accounts"),
            ({"deploymentmanager.deployments.update"}, "Modify deployments of resources in GCP"),
            ({"deploymentmanager.deployments.setIamPolicy"}, "Give yourself Needed access for privesc"),
        ],
        "iam": [
            ({"iam.roles.update", "iam.roles.get"}, "Update a role assigned to you and give yourself extra permissions"),
            ({"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.get"}, "Aequest an access token that belongs to a Service Account"),
            ({"iam.serviceAccountKeys.create"}, "Create a user-managed key for a Service Account"),
            ({"iam.serviceAccounts.implicitDelegation"}, "Create a token for another Service Account with iam.serviceAccounts.getAccessToken"),
            ({"iam.serviceAccounts.signBlob"}, "Create an unsigned JWT of the SA and then send it as a blob to get the JWT signed"),
            ({"iam.serviceAccounts.signJwt"}, "Sign well-formed JSON web tokens (JWTs)"),
            ({"iam.serviceAccounts.setIamPolicy"}, "Grant yourself the permissions you need to impersonate the service account"),
            ({"iam.serviceAccounts.actAs"}, "Essential for executing various tasks, gives you actAs ability"),
            ({"iam.serviceAccounts.getOpenIdToken"}, "Generate an OpenID JWT"),
        ],
        "kms": [
            ({"cloudkms.cryptoKeyVersions.useToDecrypt"}, "Decrypt information with the key"),
            ({"cloudkms.cryptoKeys.setIamPolicy"}, "Give yourself permissions to use the key to decrypt information"),
            ({"cloudkms.cryptoKeyVersions.useToDecryptViaDelegation"}, "This allows you to request KMS to decrypt data on behalf of different Service Account"),
        ],
        "pubsub": [
            ({"pubsub.snapshots.create"}, "Create a snapshot of a topic to access all the messages, avoiding access the topic directly"),
            ({"pubsub.snapshots.setIamPolicy"}, "Give yourself permissions - pubsub.snapshots.create"),
            ({"pubsub.subscriptions.create"}, "Create a push subscription in a topic"),
            ({"pubsub.subscriptions.update"}, "Set your own URL as push endpoint to steal the messages"),
            ({"pubsub.subscriptions.consume"}, "Access messages using the subscription"),
            ({"pubsub.subscriptions.setIamPolicy"}, "Give yourself any of the subscription permissions"),
        ],
        "orgpolicy": [
            ({"orgpolicy.policy.set"}, "Manipulate organizational policies"),
        ],
        "resourcemanager": [
            ({"resourcemanager.organizations.setIamPolicy"}, "Modify your permissions against any resource at organization level"),
            ({"resourcemanager.folders.setIamPolicy"}, "Modify your permissions against any resource at folder level"),
            ({"resourcemanager.projects.setIamPolicy"}, "Modify your permissions against any resource at project level"),
        ],
        "run": [
            ({"run.services.create", "iam.serviceAccounts.actAs", "run.routes.invoke"}, "Create a run service running arbitrary code"),
            ({"run.services.update", "iam.serviceAccounts.actAs"}, "Update a run service running arbitrary code"),
            ({"run.services.setIamPolicy"}, "Give yourself any of the run services permissions"),
            ({"run.jobs.create", "run.jobs.run", "iam.serviceaccounts.actAs", "run.jobs.get"}, "Launch a job with a reverse shell to steal the service account indicated in the command"),
            ({"run.jobs.update", "run.jobs.run", "iam.serviceaccounts.actAs", "run.jobs.get"}, "Update a job and update the SA"),
            ({"run.jobs.setIamPolicy"}, "Give yourself permissions over Cloud Jobs"),
            ({"run.jobs.run", "run.jobs.runWithOverrides", "run.jobs.get"}, "Abuse the env variables of a job execution to execute arbitrary code"),
        ],
        "secretmanager": [
            ({"secretmanager.versions.access"}, "Read the secrets from the secret manager"),
            ({"secretmanager.secrets.setIamPolicy"}, "Give yourself access to read the secrets from the secret manager"),
        ],
        "serviceusage": [
            ({"serviceusage.apiKeys.create"}, "Create API keys"),
            ({"serviceusage.apiKeys.list"}, "List API keys"),
            ({"serviceusage.services.enable", "serviceusage.services.use"}, "Enable and use new services in the project"),
        ],
        "sourcerepos": [
            ({"source.repos.get"}, "Download the repository locally"),
            ({"source.repos.update"}, "Write code inside a repository cloned with gcloud source repos clone <repo>"),
            ({"source.repos.setIamPolicy"}, "Give youself permissions on source repos"),
        ],
        "storage": [
            ({"storage.objects.get"}, "Download files stored inside Cloud Storage"),
            ({"storage.objects.setIamPolicy"}, "Give youself additional storage object privileges"),
            ({"storage.buckets.setIamPolicy"}, "Give youself additional storage buckets privileges"),
            ({"storage.hmacKeys.create"}, "Create HMAC keys for Service Accounts and users"),
            ({"storage.objects.create", "storage.objects.delete"}, "Storage Write permissions"),
        ],
        "workflows": [
            ({"workflows.workflows.create", "iam.serviceAccounts.ActAs", "workflows.executions.create", "workflows.workflows.get", "workflows.operations.get"}, "Get a shell with access to the metadata endpoint containing the SA credentials"),
            ({"workflows.workflows.update"}, "Update an already existing workflow"),
        ],
    }

    privesc_links = {
        "apikeys": "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-apikeys-privesc.md",
        "appengine": "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-appengine-privesc.md",
        "artifactregistry": "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-artifact-registry-privesc.md",
        "batch":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-batch-privesc.md",
        "bigquery":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigquery-privesc.md",
        "clientauthconfig":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-clientauthconfig-privesc.md",
        "cloudbuild":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudbuild-privesc.md",
        "cloudfunctions":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudfunctions-privesc.md",
        "cloudidentity":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudidentity-privesc.md",
        "cloudscheduler":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudscheduler-privesc.md",
        "composer":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-composer-privesc.md",
        "container":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-container-privesc.md",
        "dataproc":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-dataproc-privesc.md",
        "deploymentmanager":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-deploymentmaneger-privesc.md",
        "iam":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-iam-privesc.md",
        "kms":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-kms-privesc.md",
        "pubsub":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-pubsub-privesc.md",
        "iam":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-iam-privesc.md",
        "orgpolicy":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-orgpolicy-privesc.md",
        "resourcemanager":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-resourcemanager-privesc.md",
        "run":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-iam-privesc.md",
        "secretmanager":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secretmanager-privesc.md",
        "serviceusage":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-serviceusage-privesc.md",
        "sourcerepos":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-sourcerepos-privesc.md",
        "storage":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-storage-privesc.md",
        "workflows":"https://github.com/HackTricks-wiki/hacktricks-cloud/blob/master/src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workflows-privesc.md",
      }

    for service, conditions in privesc_conditions.items():
        for required_perms, attack_name in conditions:
            if required_perms.issubset(perms_set):  
                detected_privesc[attack_name] = {
                    "permissions": list(required_perms),
                    "link": privesc_links.get(service)
                }

    return detected_privesc

""""
# Debugging
def main():
   
    
    # Read permissions from file (one per line)
    file_path = "perms.txt"
    try:
        with open(file_path, "r") as file:
            perms_list = [line.strip() for line in file if line.strip()]  # Remove empty lines
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return
    
    # Check privilege escalation
    detected_privesc = check_privesc(perms_list)


    # Print results
    if detected_privesc:
        print("🚨 Detected Privilege Escalation Paths:\n")
        for attack_name, details in detected_privesc.items():
            print(f"⚠️ {attack_name}:")
            print("  📜 Required Permissions:")
            for perm in details["permissions"]:
                print(f"    - {perm}")
            if details["link"]:
                print(f"  🔗 More Info: {details['link']}")
            print()  # Add a newline for readability
    else:
        print("✅ No privilege escalation detected.")

if __name__ == "__main__":
    main()

"""    