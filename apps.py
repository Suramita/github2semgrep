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
import datetime

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Configuration from Environment Variables ---
DD_API_URL = os.getenv('DD_API_URL', 'http://172.18.5.55:8080/api/v2')
DD_API_KEY = os.getenv('DD_API_KEY')
DD_PRODUCT_ID = os.getenv('DD_PRODUCT_ID')
DD_ENGAGEMENT_NAME_PREFIX = os.getenv('DD_ENGAGEMENT_NAME_PREFIX', 'SAST Scan for')
DD_ENGAGEMENT_LEAD_ID = os.getenv('DD_ENGAGEMENT_LEAD_ID', '1')
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', 'your_super_secret_webhook_key')
SEMGREP_RULES = os.getenv('SEMGREP_RULES', 'p/ci')
SEMGREP_DOCKER_IMAGE = os.getenv('SEMGREP_DOCKER_IMAGE', 'returntocorp/semgrep')
SEMGREP_APP_TOKEN = os.getenv('SEMGREP_APP_TOKEN', '')

# Validate critical environment variables
def validate_env_vars():
    missing_vars = []
    if not DD_API_KEY:
        missing_vars.append("DD_API_KEY")
    if not DD_PRODUCT_ID:
        missing_vars.append("DD_PRODUCT_ID")
    if missing_vars:
        app.logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

validate_env_vars()

# --- Helper Functions ---
def verify_webhook_signature(payload_body, secret_token, signature_header):
    if not signature_header:
        app.logger.warning("No signature header provided. Cannot verify webhook authenticity.")
        return False

    if signature_header.startswith('sha256='):
        alg, signature = signature_header.split('=')
        expected_signature = hmac.new(secret_token.encode('utf-8'), payload_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            app.logger.error(f"GitHub signature mismatch. Expected: {expected_signature}, Got: {signature}")
            return False
        return True
    elif signature_header == secret_token:
        return True
    elif signature_header.startswith('sha256:'):
        alg, signature = signature_header.split(':')
        expected_signature = hmac.new(secret_token.encode('utf-8'), payload_body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature):
            app.logger.error(f"Gitea signature mismatch. Expected: {expected_signature}, Got: {signature}")
            return False
        return True

    app.logger.warning(f"Unknown or unsupported signature header format: {signature_header}")
    return False

def run_sast_scan(repo_path, output_path):
    app.logger.info(f"Starting Semgrep scan on {repo_path} using Docker image: {SEMGREP_DOCKER_IMAGE}")
    docker_repo_path = '/src'
    docker_output_path = '/output/semgrep.json'

    # Validate SEMGREP_RULES
    if not SEMGREP_RULES or SEMGREP_RULES.strip() == "":
        app.logger.error("SEMGREP_RULES is not set or is empty. Please provide valid Semgrep rules.")
        return False

    try:
        # Construct Semgrep command to be run inside the Docker container
        semgrep_command_in_docker = [
            'semgrep',
            f'--config={SEMGREP_RULES}',
            '--metrics=off',
            '--json',
            f'--output={docker_output_path}',
            docker_repo_path
        ]

        # Construct the full Docker command
        docker_run_command = [
            'docker', 'run', '--rm',
            '-v', f"{repo_path}:{docker_repo_path}",
            '-v', f"{os.path.dirname(output_path)}:/output",
        ]

        # Add Semgrep token if available
        if SEMGREP_APP_TOKEN:
            docker_run_command.extend(['-e', f'SEMGREP_APP_TOKEN={SEMGREP_APP_TOKEN}'])
            app.logger.info("Using SEMGREP_APP_TOKEN for authenticated registry access.")

        docker_run_command.extend([SEMGREP_DOCKER_IMAGE, *semgrep_command_in_docker])

        app.logger.debug(f"Docker command: {' '.join(docker_run_command)}")
        result = subprocess.run(docker_run_command, capture_output=True, text=True, check=False)

        app.logger.info(f"Semgrep scan result: {result}")
        app.logger.info(f"Semgrep stdout: {result.stdout}")
        app.logger.info(f"Semgrep stderr: {result.stderr}")

        if result.returncode == 0:
            app.logger.info("Semgrep Docker scan completed successfully (no findings or informational exit).")
        elif result.returncode == 1:
            app.logger.info("Semgrep Docker scan completed successfully (findings were identified).")
        else:
            app.logger.error(f"Semgrep Docker scan failed with exit code: {result.returncode}")
            app.logger.error(f"Semgrep stderr: {result.stderr}")
            return False

        return True
    except FileNotFoundError:
        app.logger.error("Docker command not found. Ensure Docker CLI is installed and accessible.")
        return False
    except Exception as e:
        app.logger.error(f"Unexpected error during Semgrep scan: {e}", exc_info=True)
        return False

def import_scan_to_defectdojo(product_id, engagement_name, scan_file_path):
    app.logger.info(f"Importing scan results to DefectDojo for product ID {product_id} and engagement '{engagement_name}'")
    headers = {
        'Authorization': f'Token {DD_API_KEY}',
        'accept': 'application/json'
    }
    files = {
        'file': (os.path.basename(scan_file_path), open(scan_file_path, 'rb'), 'application/json')
    }
    data = {
        'engagement': engagement_name,
        'scan_type': 'Semgrep JSON',
        'active': True,
        'verified': False,
        'push_to_jira': False,
        'close_old_findings': True,
        'skip_duplicates': True
    }

    try:
        response = requests.post(f"{DD_API_URL}/import-scan/", headers=headers, files=files, data=data)
        app.logger.info(f"DefectDojo response: {response.status_code} - {response.text}")
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Failed to import scan to DefectDojo: {e}", exc_info=True)
        return False
    finally:
        files['file'][1].close()

# Flask Routes
@app.route('/', methods=['GET'])
def hello_world():
    return "SAST Webhook Listener is running and awaiting webhook events!"

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    app.logger.info("Received webhook request.")
    payload_body = request.get_data()
    github_signature = request.headers.get('X-Hub-Signature-256')
    gitlab_token = request.headers.get('X-Gitlab-Token')
    gitea_signature = request.headers.get('X-Gitea-Signature')
    signature_header = github_signature or gitlab_token or gitea_signature

    if not verify_webhook_signature(payload_body, WEBHOOK_SECRET, signature_header):
        app.logger.error("Webhook signature verification failed.")
        return jsonify({'status': 'error', 'message': 'Invalid webhook signature'}), 401

    try:
        payload = request.json
        if payload is None:
            raise ValueError("Payload is None, likely not valid JSON or empty body.")
        app.logger.info(f"Webhook payload: {json.dumps(payload, indent=2)}")
    except (json.JSONDecodeError, ValueError) as e:
        app.logger.error(f"Failed to parse JSON payload: {e}")
        app.logger.debug(f"Raw payload body: {payload_body.decode('utf-8', errors='ignore')}")
        return jsonify({'status': 'error', 'message': 'Invalid JSON payload'}), 400

    # Extract repository information
    repo_url = payload.get('repository', {}).get('clone_url')
    branch = payload.get('ref', '').split('/')[-1]
    if not repo_url or not branch:
        app.logger.error("Repository URL or branch not found in payload.")
        return jsonify({'status': 'error', 'message': 'Repository URL or branch not found in payload.'}), 400

    # Clone repository and run Semgrep scan
    temp_dir = tempfile.mkdtemp(prefix='sast-scan-')
    repo_path = os.path.join(temp_dir, 'repo')
    output_path = os.path.join(temp_dir, 'semgrep_results.json')

    try:
        app.logger.info(f"Cloning repository {repo_url} into {repo_path}")
        git.Repo.clone_from(repo_url, repo_path, branch=branch)
        app.logger.info("Repository cloned successfully.")

        app.logger.info("Running Semgrep scan...")
        if not run_sast_scan(repo_path, output_path):
            return jsonify({'status': 'error', 'message': 'Semgrep scan failed.'}), 500

        app.logger.info("Importing scan results to DefectDojo...")
        if not import_scan_to_defectdojo(DD_PRODUCT_ID, f"{DD_ENGAGEMENT_NAME_PREFIX} {branch}", output_path):
            return jsonify({'status': 'error', 'message': 'Failed to import scan results to DefectDojo.'}), 500

        app.logger.info("Scan completed and results imported to DefectDojo successfully.")
        return jsonify({'status': 'success', 'message': 'Scan completed and results imported to DefectDojo.'}), 200
    except Exception as e:
        app.logger.error(f"An error occurred: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'An internal error occurred.'}), 500
    finally:
        app.logger.info(f"Cleaing up tmporary diasasdasda asdasdrectory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)