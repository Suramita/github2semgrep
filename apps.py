import os
import hmac
import hashlib
import json
import subprocess
import tempfile
import shutil
from dotenv import load_dotenv
from flask import Flask, request, jsonify
import requests
import git
import datetime # For dynamic target_start/end dates

# Load environment variables from .env file
# This is crucial for securely managing sensitive information like API keys and secrets.
load_dotenv()

app = Flask(__name__)

# --- Configuration from Environment Variables ---
# It is HIGHLY recommended to use environment variables for sensitive data.
# Do NOT hardcode these values in your script in a production environment.

# DefectDojo API details
DD_API_URL = os.getenv('DD_API_URL', 'http://localhost:8080/api/v2') # Your DefectDojo API URL (e.g., http://your-dojo-instance/api/v2)
DD_API_KEY = os.getenv('DD_API_KEY') # Your DefectDojo API Key
DD_PRODUCT_ID = os.getenv('DD_PRODUCT_ID') # The ID of the DefectDojo Product to associate with scans
DD_ENGAGEMENT_NAME_PREFIX = os.getenv('DD_ENGAGEMENT_NAME_PREFIX', 'SAST Scan for') # Prefix for engagement names
DD_ENGAGEMENT_LEAD_ID = os.getenv('DD_ENGAGEMENT_LEAD_ID', '1') # User ID in DefectDojo to assign as engagement lead. Change this to a valid user ID in your DefectDojo instance.

# Webhook secret (for validating GitHub/GitLab webhooks)
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', 'your_super_secret_webhook_key') # MUST be kept secret and match your Git webhook configuration

# SAST tool configuration (for local Semgrep CLI execution via Docker)
SEMGREP_RULES = os.getenv('SEMGREP_RULES', 'p/python,p/javascript,p/go,p/java,p/typescript,p/csharp') # Semgrep rules to run (e.g., 'p/python,p/javascript' or a path to a custom rule file)
SEMGREP_CONFIG_PATH = os.getenv('SEMGREP_CONFIG_PATH', '') # Optional: Path to a Semgrep config file (e.g., './.semgrep/config.yaml')
SEMGREP_DOCKER_IMAGE = os.getenv('SEMGREP_DOCKER_IMAGE', 'semgrep/semgrep:latest') # Docker image for Semgrep CLI

# Check if essential environment variables are set
if not DD_API_KEY or not DD_PRODUCT_ID:
    app.logger.error("DD_API_KEY or DD_PRODUCT_ID environment variables are not set. Exiting.")
    # In a real application, you might want to raise an exception or exit.
    # For a Flask app, returning an error response is more appropriate.
    # For now, we'll log and let the app start but it won't function correctly.

# --- Helper Functions ---

def verify_webhook_signature(payload_body, secret_token, signature_header):
    """
    Verifies the signature of the incoming webhook payload.
    This helps ensure that the request truly came from your Git provider.
    Supports GitHub (X-Hub-Signature-256), GitLab (X-Gitlab-Token), and Gitea (X-Gitea-Signature).
    """
    if not signature_header:
        app.logger.warning("No signature header provided. Cannot verify webhook authenticity.")
        return False

    # GitHub signature verification (HMAC SHA256)
    if signature_header.startswith('sha256='):
        alg, signature = signature_header.split('=')
        expected_signature = hmac.new(secret_token.encode('utf-8'), payload_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            app.logger.error(f"GitHub signature mismatch. Expected: {expected_signature}, Got: {signature}")
            return False
        return True
    # GitLab signature verification (token directly in header)
    elif signature_header == secret_token:
        return True
    # Gitea signature verification (HMAC SHA256, similar to GitHub but 'sha256:' prefix)
    elif signature_header.startswith('sha256:'):
        alg, signature = signature_header.split(':')
        expected_signature = hmac.new(secret_token.encode('utf-8'), payload_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            app.logger.error(f"Gitea signature mismatch. Expected: {expected_signature}, Got: {signature}")
            return False
        return True
    
    app.logger.warning(f"Unknown or unsupported signature header format: {signature_header}")
    return False


def get_repository_info(event_type, payload):
    """
    Extracts repository URL, branch, commit hash, commit message, and pusher name
    from webhook payload, handling different Git provider formats (GitHub, GitLab, Gitea).
    """
    repo_url = None
    branch = None
    commit_hash = None
    commit_message = ""
    pusher = ""

    # Common fields for push events across providers
    if 'repository' in payload:
        repo_url = payload['repository'].get('clone_url') or payload['repository'].get('html_url') + '.git' # GitLab sometimes uses html_url + .git

    if 'ref' in payload and payload['ref'].startswith('refs/heads/'):
        branch = payload['ref'].split('/')[-1]

    # Handle commit details for push events
    if 'commits' in payload and payload['commits']:
        latest_commit = payload['commits'][0] # Often the latest commit is the first in the list
        commit_hash = latest_commit.get('id')
        commit_message = latest_commit.get('message', '').split('\n')[0] # First line of message
        pusher = latest_commit.get('author', {}).get('name', 'Unknown')
    elif 'head_commit' in payload and payload['head_commit']: # GitHub specific
        latest_commit = payload['head_commit']
        commit_hash = latest_commit.get('id')
        commit_message = latest_commit.get('message', '').split('\n')[0]
        pusher = latest_commit.get('author', {}).get('name', 'Unknown')

    # Handle Pull Request / Merge Request events (specifics for GitHub/GitLab/Gitea)
    if event_type == 'pull_request': # GitHub Pull Request
        if 'pull_request' in payload:
            pr = payload['pull_request']
            repo_url = pr['head']['repo']['clone_url']
            branch = pr['head']['ref']
            commit_hash = pr['head']['sha']
            commit_message = pr.get('title', '')
            pusher = pr.get('user', {}).get('login', 'Unknown')
    elif event_type == 'merge_request': # GitLab Merge Request
        if 'object_attributes' in payload:
            mr = payload['object_attributes']
            if 'source' in mr and 'web_url' in mr['source']:
                repo_url = mr['source']['web_url'] + '.git'
            branch = mr.get('target_branch')
            if 'last_commit' in mr and mr['last_commit']:
                commit_hash = mr['last_commit'].get('id')
            commit_message = mr.get('title', '')
            if 'user' in payload:
                pusher = payload['user'].get('username', 'Unknown')
    elif event_type == 'create' and payload.get('ref_type') == 'branch': # Gitea branch creation (often includes a push)
        # Gitea 'create' event for a branch usually means a push of an initial commit
        if 'repository' in payload:
            repo_url = payload['repository'].get('clone_url')
        branch = payload.get('ref')
        # Gitea's create event doesn't directly give commit, rely on subsequent push or generic commit handling above.

    # Final check for missing info, especially branch
    if not branch and 'default_branch' in payload.get('repository', {}):
        branch = payload['repository']['default_branch'] # Fallback to default branch if push event doesn't specify ref
    
    if not repo_url or not branch:
        app.logger.error(f"Could not extract repo_url ({repo_url}) or branch ({branch}) from payload for event type: {event_type}")
        return None, None, None, None, None

    app.logger.info(f"Extracted: Repo URL: {repo_url}, Branch: {branch}, Commit: {commit_hash}, Pusher: {pusher}")
    return repo_url, branch, commit_hash, commit_message, pusher


def run_sast_scan(repo_path, output_path):
    """
    Runs Semgrep on the cloned repository using the Docker CLI.
    The results are saved to a specified JSON file.
    """
    app.logger.info(f"Starting Semgrep scan on {repo_path} using Docker image: {SEMGREP_DOCKER_IMAGE}")
    
    # Define a path inside the Semgrep Docker container where the repository will be mounted
    docker_repo_path = '/src'
    # Define a path inside the Semgrep Docker container where the output will be written
    docker_output_path = '/output/semgrep_results.json'

    try:
        # Construct Semgrep command to be run inside the Docker container
        semgrep_command_in_docker = [
            'semgrep',
            f'--config={SEMGREP_RULES}', # Use --config for multiple rules or a rule file path
            '--json',
            f'--output={docker_output_path}',
            '--metrics=off', # Disable metrics for faster execution in CI
            '--verbose', # Added for more detailed output
            docker_repo_path
        ]
        
        # Add optional custom config path if specified (e.g., for .semgrep/config.yaml)
        # Note: If SEMGREP_CONFIG_PATH is outside repo_path, you'd need another volume mount.
        # Assuming it's inside repo_path or handled by Semgrep's default behavior.
        if SEMGREP_CONFIG_PATH:
            app.logger.warning("SEMGREP_CONFIG_PATH is set. Ensure it's correctly accessible within the Dockerized Semgrep environment.")
            semgrep_command_in_docker.insert(1, f'--config={SEMGREP_CONFIG_PATH}')

        # Construct the full Docker command
        # We need to mount the cloned repository path and the output file's directory
        # The output file is created in temp_dir which is on the host filesystem relative to this app.
        # We also need to mount the Docker socket to allow this container to run another Docker command.
        docker_run_command = [
            'docker', 'run', '--rm',
            '-v', f"{repo_path}:{docker_repo_path}", # Mount the cloned repo
            '-v', f"{os.path.dirname(output_path)}:/output", # Mount the directory for results
            # Explicitly set SEMGREP_FEATURES=oss for the spawned Semgrep container
            '-e', 'SEMGREP_FEATURES=oss', 
            SEMGREP_DOCKER_IMAGE,
            *semgrep_command_in_docker # Unpack the Semgrep command arguments
        ]

        app.logger.debug(f"Docker command: {' '.join(docker_run_command)}")

        # Run the Docker process
        # `check=False` allows Semgrep to exit with 1 for findings without raising an error.
        result = subprocess.run(docker_run_command, capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            app.logger.info("Semgrep Docker scan completed successfully (no findings or informational exit).")
        elif result.returncode == 1:
            app.logger.info("Semgrep Docker scan completed successfully (findings were identified).")
        else:
            app.logger.error(f"Semgrep Docker scan failed with exit code: {result.returncode}")
            app.logger.error(f"Semgrep stdout: {result.stdout}")
            app.logger.error(f"Semgrep stderr: {result.stderr}")
            return False

        if result.stdout:
            app.logger.debug(f"Semgrep Docker stdout: {result.stdout}")
        if result.stderr:
            app.logger.warning(f"Semgrep Docker stderr: {result.stderr}")
        return True
    except FileNotFoundError:
        app.logger.error("Docker command not found. Please ensure Docker CLI is installed and in your PATH within this container, and that docker.sock is mounted.")
        return False
    except Exception as e:
        app.logger.error(f"An unexpected error occurred during Dockerized Semgrep scan: {e}", exc_info=True)
        return False


def import_scan_to_defectdojo(product_id, engagement_name, scan_file_path, scan_type, branch_name, commit_hash, commit_message, pusher):
    """
    Imports the SAST scan results into DefectDojo using its API.
    It attempts to find an existing engagement first, otherwise creates a new one.
    """
    headers = {
        'Authorization': f'Token {DD_API_KEY}',
        'accept': 'application/json',
        'Content-Type': 'application/json' # For JSON payloads like engagement creation
    }
    
    # --- Try to find an existing engagement for the branch ---
    # This logic attempts to find an "In Progress" engagement with a matching name.
    # If found, it updates that engagement. Otherwise, it creates a new one.
    
    full_engagement_name = f"{DD_ENGAGEMENT_NAME_PREFIX} {branch_name}"
    engagement_id = None
    
    app.logger.info(f"Checking for existing 'In Progress' engagement '{full_engagement_name}' for product ID {product_id}...")
    
    try:
        # Search for existing engagements by name and product ID
        search_params = {
            'product': product_id,
            'name': full_engagement_name,
            'status': 'In Progress' # Only consider active engagements
        }
        response = requests.get(f"{DD_API_URL}/engagements/", headers=headers, params=search_params)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        
        engagements_data = response.json()
        if engagements_data and engagements_data.get('count', 0) > 0:
            engagement_id = engagements_data['results'][0]['id']
            app.logger.info(f"Found existing engagement ID: {engagement_id} (Name: {engagements_data['results'][0]['name']}). Will update.")
        else:
            app.logger.info(f"No existing 'In Progress' engagement found with name '{full_engagement_name}'. Creating a new one.")
            
            # --- If no existing engagement, create a new one ---
            current_date = datetime.date.today().isoformat()
            engagement_payload = {
                'name': full_engagement_name,
                'product': product_id,
                'lead': DD_ENGAGEMENT_LEAD_ID, # Ensure this ID exists in your DefectDojo users
                'target_start': current_date,
                'target_end': current_date,
                'status': 'In Progress',
                'description': (f"Automated SAST scan for branch: {branch_name}\n"
                                f"Commit: {commit_hash[:8] if commit_hash else 'N/A'} - {commit_message}\n"
                                f"Pusher: {pusher}"),
                'engagement_type': 'CI/CD' # Or 'Continuous' for recurring scans
            }
            create_engagement_response = requests.post(f"{DD_API_URL}/engagements/", headers=headers, json=engagement_payload)
            create_engagement_response.raise_for_status()
            engagement_id = create_engagement_response.json()['id']
            app.logger.info(f"Successfully created new engagement with ID: {engagement_id}")

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error creating/finding DefectDojo engagement: {e}")
        if hasattr(e, 'response') and e.response is not None:
            app.logger.error(f"DefectDojo API response content: {e.response.text}")
        return False

    # --- Import the scan results ---
    if not engagement_id:
        app.logger.error("Could not determine or create engagement ID for scan import.")
        return False

    app.logger.info(f"Importing scan file '{scan_file_path}' (Type: {scan_type}) to DefectDojo engagement ID: {engagement_id}")
    
    # Files and data for the multipart/form-data request for scan import
    files = {
        'file': (os.path.basename(scan_file_path), open(scan_file_path, 'rb'), 'application/json')
    }
    data = {
        'engagement': engagement_id,
        'scan_type': scan_type,
        'active': True,
        'verified': False,
        'push_to_jira': False,
        'tags': f'branch:{branch_name},commit:{commit_hash[:8] if commit_hash else "N/A"}',
        'skip_duplicates': True, # Recommended: Avoid creating duplicate findings for the same vulnerability
        'close_old_findings': True, # Recommended: Close findings that are no longer present in the new scan
        'minimum_severity': 'Info', # Adjust the minimum severity to import (Info, Low, Medium, High, Critical)
        'auto_create_context': True # Automatically create product, engagement, etc. if not found (though we handle product/engagement explicitly here)
    }

    try:
        # Note: When sending files with `requests`, you should NOT set the 'Content-Type' header
        # manually for the request, as `requests` will set it correctly to `multipart/form-data`
        # with the correct boundary when the `files` parameter is used.
        response = requests.post(
            f"{DD_API_URL}/import-scan/",
            headers={'Authorization': f'Token {DD_API_KEY}', 'accept': 'application/json'}, # Only these headers are needed for files
            files=files,
            data=data
        )
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        app.logger.info(f"Scan import to DefectDojo successful! Response: {response.json()}")
        return True
    except requests.exceptions.HTTPError as e:
        app.logger.error(f"HTTP Error importing scan to DefectDojo: {e}")
        app.logger.error(f"Response content: {e.response.text}")
        return False
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error importing scan to DefectDojo: {e}", exc_info=True)
        return False
    finally:
        # Ensure the file is closed after the request is sent
        for f in files.values():
            if hasattr(f, 'close'):
                f[1].close() # The actual file object is at index 1 of the tuple



### Flask Routes

@app.route('/', methods=['GET'])
def hello_world():
    """Simple health check endpoint."""
    return "SAST Webhook Listener is running and awaiting webhook events!"

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """
    Main webhook endpoint that receives payloads from Git servers.
    This function verifies the webhook signature and then triggers the CI scan endpoint.
    """
    app.logger.info("Received webhook request.")

    # 1. Get raw payload body for signature verification
    payload_body = request.get_data()

    # 2. Get signature header (varies by Git provider)
    github_signature = request.headers.get('X-Hub-Signature-256') # GitHub
    gitlab_token = request.headers.get('X-Gitlab-Token') # GitLab
    gitea_signature = request.headers.get('X-Gitea-Signature') # Gitea

    # Determine which signature header to use
    signature_header = github_signature or gitlab_token or gitea_signature

    # 3. Verify webhook signature
    if not verify_webhook_signature(payload_body, WEBHOOK_SECRET, signature_header):
        app.logger.error("Webhook signature verification failed.")
        return jsonify({'status': 'error', 'message': 'Invalid webhook signature'}), 401

    # 4. Parse JSON payload
    try:
        payload = request.json
        if payload is None:
            raise ValueError("Payload is None, likely not valid JSON or empty body.")
    except (json.JSONDecodeError, ValueError) as e:
        app.logger.error(f"Failed to parse JSON payload from webhook: {e}")
        app.logger.debug(f"Raw payload body: {payload_body.decode('utf-8', errors='ignore')}")
        return jsonify({'status': 'error', 'message': 'Invalid JSON payload'}), 400

    # 5. Determine event type and extract repository info
    event_type = request.headers.get('X-GitHub-Event') or \
                 request.headers.get('X-Gitlab-Event') or \
                 request.headers.get('X-Gitea-Event')

    supported_events = ['push', 'pull_request', 'merge_request', 'create'] 
    if event_type not in supported_events:
        app.logger.info(f"Received '{event_type}' event, but only {', '.join(supported_events)} are supported. Ignoring.")
        return jsonify({'status': 'info', 'message': f'Event type {event_type} not supported, ignoring.'}), 200

    repo_url, branch, commit_hash, commit_message, pusher = get_repository_info(event_type, payload)

    if not repo_url or not branch:
        app.logger.error(f"Could not extract sufficient repository information for event type: {event_type}.")
        return jsonify({'status': 'error', 'message': 'Could not extract repository information from webhook payload.'}), 400

    app.logger.info(f"Successfully received webhook for repo: {repo_url}, branch: {branch}. Triggering CI scan.")

    # 6. Prepare payload for internal CI trigger and send it
    scan_payload = {
        'repo_url': repo_url,
        'branch': branch,
        'commit_hash': commit_hash,
        'commit_message': commit_message,
        'pusher': pusher
    }
    
    try:
        # Send an internal POST request to the CI trigger endpoint.
        # Use 'http://localhost:5000' as the Flask app listens on this address
        # within the Docker container or local environment.
        internal_trigger_url = 'http://localhost:5000/trigger-ci.json' 
        response = requests.post(internal_trigger_url, json=scan_payload)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        
        app.logger.info(f"CI scan trigger successful for {repo_url} on branch {branch}.")
        # Return 202 Accepted, as the actual scan is being processed asynchronously
        return jsonify({'status': 'success', 'message': 'Webhook received and CI scan triggered.'}), 202
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to trigger CI scan internally: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Failed to trigger CI scan internally: {e}'}), 500


@app.route('/trigger-ci.json', methods=['POST'])
def trigger_ci_scan():
    """
    Endpoint to trigger the SAST scan and DefectDojo import.
    This endpoint is expected to be called internally by the /webhook endpoint
    or could be called directly by another CI system.
    """
    app.logger.info("Received request to trigger CI scan.")
    
    temp_dir = None # Initialize temp_dir outside try block for finally cleanup

    try:
        # 1. Parse scan details from the request body
        scan_details = request.json
        if not scan_details:
            app.logger.error("No scan details provided in request body for /trigger-ci.json.")
            return jsonify({'status': 'error', 'message': 'No scan details provided in payload'}), 400

        repo_url = scan_details.get('repo_url')
        branch = scan_details.get('branch')
        commit_hash = scan_details.get('commit_hash')
        commit_message = scan_details.get('commit_message', '')
        pusher = scan_details.get('pusher', 'Unknown')

        if not repo_url or not branch:
            app.logger.error("Missing repo_url or branch in CI trigger payload.")
            return jsonify({'status': 'error', 'message': 'Missing repository information in payload'}), 400

        app.logger.info(f"Starting CI scan for repo: {repo_url}, branch: {branch}, commit: {commit_hash[:8] if commit_hash else 'N/A'}, pusher: {pusher}")

        # 2. Create a temporary directory for cloning and scanning
        temp_dir = tempfile.mkdtemp(prefix='sast-scan-')
        scan_output_file = os.path.join(temp_dir, 'semgrep_results.json')
        repo_clone_path = os.path.join(temp_dir, 'cloned_repo')

        # 3. Clone the repository
        app.logger.info(f"Cloning {repo_url} into {repo_clone_path} (branch: {branch})...")
        try:
            # GitPython can clone directly to a specific branch
            git.Repo.clone_from(repo_url, repo_clone_path, branch=branch)
            app.logger.info("Repository cloned successfully.")
        except git.exc.GitCommandError as e:
            app.logger.error(f"Git clone failed: {e}. Ensure the branch '{branch}' exists and repository is accessible.")
            app.logger.error(f"Git stderr: {e.stderr}")
            return jsonify({'status': 'error', 'message': f'Git clone failed: {e}'}), 500

        # 4. Run SAST scan (local Semgrep CLI via Docker)
        scan_successful = run_sast_scan(repo_clone_path, scan_output_file)

        if not scan_successful:
            app.logger.error("SAST scan failed to complete successfully.")
            return jsonify({'status': 'error', 'message': 'SAST scan failed.'}), 500

        # 5. Check if scan produced output and import to DefectDojo
        if not os.path.exists(scan_output_file) or os.path.getsize(scan_output_file) == 0:
            app.logger.warning(f"Semgrep output file {scan_output_file} is empty or does not exist. No findings or an error occurred during scan output.")
            return jsonify({'status': 'success', 'message': 'Scan completed, but output file was empty. No findings to import.'}), 200

        import_successful = import_scan_to_defectdojo(
            product_id=DD_PRODUCT_ID,
            engagement_name=f"{DD_ENGAGEMENT_NAME_PREFIX} {branch}",
            scan_file_path=scan_output_file,
            scan_type='Semgrep JSON', # DefectDojo supports Semgrep JSON directly
            branch_name=branch,
            commit_hash=commit_hash,
            commit_message=commit_message,
            pusher=pusher
        )

        if not import_successful:
            app.logger.error("Failed to import scan to DefectDojo.")
            return jsonify({'status': 'error', 'message': 'Failed to import scan to DefectDojo.'}), 500

        app.logger.info("CI scan and DefectDojo import completed successfully.")
        return jsonify({'status': 'success', 'message': 'CI scan completed and results sent to DefectDojo.'}), 200

    except Exception as e:
        app.logger.error(f"An unexpected error occurred during CI scan trigger: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'An internal server error occurred: {e}'}), 500
    finally:
        # 6. Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            app.logger.info(f"Cleaning up temporary directory: {temp_dir}")
            shutil.rmtree(temp_dir)
        else:
            app.logger.warning("Temporary directory not cleaned up (might not have been created or an early error occurred).")


if __name__ == '__main__':
    # Create an .env file if it doesn't exist to guide user configuration.
    # This block only runs when the script is executed directly (not when imported).
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write("# .env file for SAST Webhook Listener\n")
            f.write("# IMPORTANT: Replace placeholder values with your actual DefectDojo details and a strong secret.\n")
            f.write("DD_API_URL=\"http://localhost:8080/api/v2\"\n")
            f.write("DD_API_KEY=\"your_defectdojo_api_key_here\"\n")
            f.write("DD_PRODUCT_ID=\"1\" # Replace with your DefectDojo Product ID (e.g., 1, 2, etc.)\n")
            f.write("DD_ENGAGEMENT_LEAD_ID=\"1\" # Replace with a valid User ID in your DefectDojo instance (e.g., 1, 2, etc.)\n")
            f.write("WEBHOOK_SECRET=\"your_super_secret_webhook_key\"\n")
            f.write("SEMGREP_RULES=\"p/python,p/javascript,p/go,p/java,p/typescript,p/csharp\"\n")
            f.write("SEMGREP_CONFIG_PATH=\"\" # Optional: path to a local Semgrep config file (e.g., ./.semgrep/config.yaml)\n")
            f.write("SEMGREP_DOCKER_IMAGE=\"semgrep/semgrep:latest\"\n") # Added for Dockerized Semgrep
            f.write("DD_ENGAGEMENT_NAME_PREFIX=\"SAST Scan for\"\n")
            print("\n--- .env file created ---")
            print("Please edit the '.env' file with your DefectDojo API key, Product ID, an Engagement Lead ID, and a strong WEBHOOK_SECRET.")
            print("Also, configure the SEMGREP_DOCKER_IMAGE if you need a specific Semgrep Docker image.")
            print("-------------------------\n")

    # Run the Flask application in debug mode (for development).
    # For production, use a WSGI server like Gunicorn behind a reverse proxy.
    app.run(debug=True, host='0.0.0.0', port=5000)
