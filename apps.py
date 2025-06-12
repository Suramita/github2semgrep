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
SEMGREP_RULES = os.getenv('SEMGREP_RULES', 'p/python,p/javascript,p/go,p/java,p/typescript,p/csharp')
SEMGREP_CONFIG_PATH = os.getenv('SEMGREP_CONFIG_PATH', '')
SEMGREP_DOCKER_IMAGE = os.getenv('SEMGREP_DOCKER_IMAGE', 'semgrep/semgrep:latest')

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
    docker_output_path = '/output/semgrep_results.json'

    try:
        semgrep_command_in_docker = [
            'semgrep',
            f'--config={SEMGREP_RULES}',
            '--json',
            f'--output={docker_output_path}',
            '--metrics=off',
            '--verbose',
            docker_repo_path
        ]
        if SEMGREP_CONFIG_PATH:
            app.logger.warning("SEMGREP_CONFIG_PATH is set. Ensure it's correctly accessible within the Dockerized Semgrep environment.")
            semgrep_command_in_docker.insert(1, f'--config={SEMGREP_CONFIG_PATH}')

        docker_run_command = [
            'docker', 'run', '--rm',
            '-v', f"{repo_path}:{docker_repo_path}",
            '-v', f"{os.path.dirname(output_path)}:/output",
            '-e', 'SEMGREP_FEATURES=oss',
            SEMGREP_DOCKER_IMAGE,
            *semgrep_command_in_docker
        ]

        app.logger.debug(f"Docker command: {' '.join(docker_run_command)}")
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
        app.logger.error("Docker command not found. Ensure Docker CLI is installed and accessible.")
        return False
    except Exception as e:
        app.logger.error(f"Unexpected error during Semgrep scan: {e}", exc_info=True)
        return False

# Flask Routes
@app.route('/', methods=['GET'])
def hello_world():
    return "SAST Webhooks Listener is running and awaiting webhook events!"

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
    except (json.JSONDecodeError, ValueError) as e:
        app.logger.error(f"Failed to parse JSON payload: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid JSON payload'}), 400

    # Additional logic for handling the webhook...
    return jsonify({'status': 'success', 'message': 'Webhook processed successfully.'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)