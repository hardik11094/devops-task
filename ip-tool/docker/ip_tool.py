#!/usr/bin/env python3
import argparse
import ipaddress
import json
import logging
import os
import smtplib
import socket
import subprocess
import sys
import datetime
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Set, Tuple, Optional, Any

# Azure imports
try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.keyvault.secrets import SecretClient
    from azure.storage.blob import BlobServiceClient, BlobClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/ip-tool.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)

# Environment variables with defaults
ENV_CONFIG = {
    'EMAIL_SENDER': os.getenv('EMAIL_SENDER', ''),
    'EMAIL_RECIPIENTS': os.getenv('EMAIL_RECIPIENTS', '').split(',') if os.getenv('EMAIL_RECIPIENTS') else [],
    'EMAIL_PASSWORD': os.getenv('EMAIL_PASSWORD', ''),
    'SMTP_SERVER': os.getenv('SMTP_SERVER', ''),
    'AZURE_CLIENT_ID': os.getenv('AZURE_CLIENT_ID', ''),
    'AZURE_CLIENT_SECRET': os.getenv('AZURE_CLIENT_SECRET', ''),
    'AZURE_TENANT_ID': os.getenv('AZURE_TENANT_ID', ''),
    'AZURE_KEYVAULT_NAME': os.getenv('AZURE_KEYVAULT_NAME', ''),
    'AZURE_STORAGE_ACCOUNT': os.getenv('AZURE_STORAGE_ACCOUNT', ''),
    'AZURE_STORAGE_CONTAINER': os.getenv('AZURE_STORAGE_CONTAINER', 'ip-tool-data'),
    'CLUSTER_NAME': os.getenv('CLUSTER_NAME', 'unknown-cluster'),
    'NOTIFICATION_THRESHOLD': int(os.getenv('NOTIFICATION_THRESHOLD', '1')),  # Number of collisions to trigger notification
    'LOG_FILE_PATH': os.getenv('LOG_FILE_PATH', '/var/log/ip-tool.log')
}


class AzureIntegration:
    """Handles all Azure-related functionality"""
    
    def __init__(self):
        """Initialize Azure integration with necessary clients"""
        self.available = AZURE_AVAILABLE
        self.kv_client = None
        self.blob_client = None
        self.initialized = False
        
        if not self.available:
            logger.warning("Azure SDK packages not installed. Azure integration disabled.")
            return
            
        if not all([ENV_CONFIG['AZURE_CLIENT_ID'], ENV_CONFIG['AZURE_CLIENT_SECRET'], 
                    ENV_CONFIG['AZURE_TENANT_ID'], ENV_CONFIG['AZURE_KEYVAULT_NAME']]):
            logger.warning("Azure credentials not fully configured. Azure integration disabled.")
            return
            
        try:
            # Create credential
            self.credential = ClientSecretCredential(
                tenant_id=ENV_CONFIG['AZURE_TENANT_ID'],
                client_id=ENV_CONFIG['AZURE_CLIENT_ID'],
                client_secret=ENV_CONFIG['AZURE_CLIENT_SECRET']
            )
            
            # Initialize Key Vault client
            keyvault_url = f"https://{ENV_CONFIG['AZURE_KEYVAULT_NAME']}.vault.azure.net/"
            self.kv_client = SecretClient(vault_url=keyvault_url, credential=self.credential)
            
            # Initialize Blob Storage client if storage account is provided
            if ENV_CONFIG['AZURE_STORAGE_ACCOUNT']:
                account_url = f"https://{ENV_CONFIG['AZURE_STORAGE_ACCOUNT']}.blob.core.windows.net"
                self.blob_client = BlobServiceClient(account_url=account_url, credential=self.credential)
                
                # Ensure container exists
                container_client = self.blob_client.get_container_client(ENV_CONFIG['AZURE_STORAGE_CONTAINER'])
                if not container_client.exists():
                    container_client.create_container()
                    logger.info(f"Created Azure Storage container: {ENV_CONFIG['AZURE_STORAGE_CONTAINER']}")
            
            self.initialized = True
            logger.info("Azure integration initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Azure integration: {str(e)}")
    
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve a secret from Azure Key Vault"""
        if not self.initialized:
            return None
            
        try:
            secret = self.kv_client.get_secret(secret_name)
            return secret.value
        except Exception as e:
            logger.error(f"Failed to retrieve secret '{secret_name}': {str(e)}")
            return None
    
    def upload_to_blob(self, data: Any, blob_name: str) -> bool:
        """Upload data to Azure Blob Storage"""
        if not self.initialized or not self.blob_client:
            logger.warning("Azure Blob Storage not configured. Skipping upload.")
            return False
            
        try:
            # Convert data to JSON if it's not already a string
            if not isinstance(data, str):
                data = json.dumps(data, indent=2)
                
            # Get blob client and upload
            blob_client = self.blob_client.get_blob_client(
                container=ENV_CONFIG['AZURE_STORAGE_CONTAINER'],
                blob=blob_name
            )
            
            blob_client.upload_blob(data, overwrite=True)
            logger.info(f"Successfully uploaded data to blob: {blob_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload to blob '{blob_name}': {str(e)}")
            return False


def send_email(subject: str, body: str, recipients: List[str] = None, is_html: bool = False) -> bool:
    """
    Send an email notification with the provided subject and body.
    
    Args:
        subject: Email subject
        body: Email body content
        recipients: List of email recipients (defaults to configured EMAIL_RECIPIENTS)
        is_html: Whether the email body is HTML content
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    if not all([ENV_CONFIG['EMAIL_SENDER'], ENV_CONFIG['EMAIL_PASSWORD'], ENV_CONFIG['SMTP_SERVER']]):
        logger.warning("Email configuration incomplete. Skipping email notification.")
        return False
        
    email_recipients = recipients if recipients else ENV_CONFIG['EMAIL_RECIPIENTS']
    if not email_recipients:
        logger.warning("No email recipients specified. Skipping email notification.")
        return False
    
    try:
        # Create the message
        msg = MIMEMultipart()
        msg['From'] = ENV_CONFIG['EMAIL_SENDER']
        msg['To'] = ", ".join(email_recipients)
        msg['Subject'] = subject

        # Add body to email
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))

        # Try to connect to the SMTP server and send email
        with smtplib.SMTP(ENV_CONFIG['SMTP_SERVER'], 587) as server:
            server.starttls()
            server.login(ENV_CONFIG['EMAIL_SENDER'], ENV_CONFIG['EMAIL_PASSWORD'])
            text = msg.as_string()
            server.sendmail(ENV_CONFIG['EMAIL_SENDER'], email_recipients, text)

        logger.info(f"Email sent successfully to {', '.join(email_recipients)}.")
        return True

    except smtplib.SMTPAuthenticationError as auth_error:
        logger.error(f"Email authentication failed: {auth_error}")
        return False

    except smtplib.SMTPConnectError as conn_error:
        logger.error(f"Email connection failed: {conn_error}")
        return False

    except smtplib.SMTPException as smtp_error:
        logger.error(f"SMTP error occurred: {smtp_error}")
        return False

    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False


def get_container_ip_networks() -> List[Dict]:
    """
    Collect all IP networks configured for the current container.
    Returns a list of dictionaries with network information.
    """
    networks = []
    
    # Get hostname and pod name (if in Kubernetes)
    hostname = socket.gethostname()
    pod_name = os.getenv('HOSTNAME', hostname)  # Kubernetes sets HOSTNAME to pod name
    pod_namespace = os.getenv('POD_NAMESPACE', 'unknown')
    
    # Get timestamp
    timestamp = datetime.datetime.now().isoformat()
    
    # Add metadata to every network entry
    metadata = {
        'hostname': hostname,
        'pod_name': pod_name,
        'pod_namespace': pod_namespace,
        'cluster_name': ENV_CONFIG['CLUSTER_NAME'],
        'timestamp': timestamp
    }
    
    # Get container IP addresses
    try:
        ip_output = subprocess.check_output(['ip', 'addr'], text=True)
        interfaces = {}
        current_if = None
        
        for line in ip_output.splitlines():
            if line.startswith(' ') and current_if and 'inet' in line:
                parts = line.strip().split()
                if parts[0] == 'inet':  # IPv4
                    cidr = parts[1]
                    network_info = {
                        'interface': current_if,
                        'network': cidr,
                        'type': 'ipv4',
                        **metadata
                    }
                    networks.append(network_info)
                elif parts[0] == 'inet6':  # IPv6
                    cidr = parts[1]
                    network_info = {
                        'interface': current_if,
                        'network': cidr,
                        'type': 'ipv6',
                        **metadata
                    }
                    networks.append(network_info)
            elif not line.startswith(' '):
                # New interface
                parts = line.split(':')
                if len(parts) > 1:
                    current_if = parts[1].strip()
    except Exception as e:
        logger.error(f"Error collecting IP information: {e}")
    
    # Add Kubernetes specific network information if available
    try:
        # Check for Kubernetes environment variables
        if 'KUBERNETES_SERVICE_HOST' in os.environ:
            # Get pod CIDR if available
            pod_cidr = os.environ.get('POD_CIDR')
            if pod_cidr:
                networks.append({
                    'interface': 'k8s-pod-network',
                    'network': pod_cidr,
                    'type': 'ipv4',
                    **metadata
                })
            
            # Get service CIDR if available
            service_cidr = os.environ.get('SERVICE_CIDR')
            if service_cidr:
                networks.append({
                    'interface': 'k8s-service-network',
                    'network': service_cidr,
                    'type': 'ipv4',
                    **metadata
                })
                
            # Try to get CNI information
            try:
                # Check if we can access CNI config
                cni_config_path = '/etc/cni/net.d/'
                if os.path.exists(cni_config_path):
                    cni_files = [f for f in os.listdir(cni_config_path) if f.endswith('.conf') or f.endswith('.conflist')]
                    for cni_file in cni_files:
                        try:
                            with open(os.path.join(cni_config_path, cni_file), 'r') as f:
                                cni_data = json.load(f)
                                # Add CNI type to metadata
                                networks.append({
                                    'interface': f'cni-{cni_data.get("name", "unknown")}',
                                    'cni_type': cni_data.get("type", "unknown"),
                                    'network': 'n/a',  # Not directly available from config
                                    'type': 'info',
                                    **metadata
                                })
                        except Exception as cni_err:
                            logger.warning(f"Error reading CNI config {cni_file}: {cni_err}")
            except Exception as cni_err:
                logger.warning(f"Error collecting CNI information: {cni_err}")
    except Exception as e:
        logger.error(f"Error collecting Kubernetes network information: {e}")
    
    return networks


def check_collisions(networks_file: str) -> List[Dict]:
    """
    Analyze the concatenated list of IP networks from the entire cluster
    and identify colliding IP networks.
    
    Args:
        networks_file: Path to a JSON file containing network information
                       from all containers in the cluster
    
    Returns:
        A list of collision information dictionaries
    """
    try:
        with open(networks_file, 'r') as f:
            network_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to open or parse networks file {networks_file}: {e}")
        return []
    
    # Basic validation of input data
    if not isinstance(network_data, list):
        logger.error(f"Invalid data format in {networks_file}: expected a list")
        return []

    # Filter out any entries that don't have the required fields
    valid_networks = []
    for item in network_data:
        if not isinstance(item, dict):
            logger.warning("Skipping non-dictionary entry in network data")
            continue
            
        if 'network' not in item or 'type' not in item:
            logger.warning(f"Skipping entry missing required fields: {item}")
            continue
            
        valid_networks.append(item)
            
    if not valid_networks:
        logger.error("No valid network entries found")
        return []
        
    logger.info(f"Analyzing {len(valid_networks)} network entries for collisions")
    
    # Group networks by type (IPv4/IPv6)
    networks_by_type = defaultdict(list)
    for net_info in valid_networks:
        if net_info['type'] in ('ipv4', 'ipv6'):
            networks_by_type[net_info['type']].append(net_info)
    
    collisions = []
    
    # Check for collisions within each type
    for net_type, networks in networks_by_type.items():
        logger.info(f"Checking {len(networks)} {net_type} networks for collisions")
        
        # Create a list of (network_obj, network_info) tuples
        parsed_networks = []
        for net_info in networks:
            try:
                # Skip entries with special meanings or info-only entries
                if net_info.get('network', '') == 'n/a':
                    continue
                    
                # Parse the network string into an ipaddress network object
                if net_type == 'ipv4':
                    net_obj = ipaddress.IPv4Network(net_info['network'], strict=False)
                else:  # ipv6
                    net_obj = ipaddress.IPv6Network(net_info['network'], strict=False)
                parsed_networks.append((net_obj, net_info))
            except ValueError as e:
                logger.warning(f"Could not parse network {net_info.get('network', '')}: {e}")
        
        # Check each network against all others for overlaps
        for i, (net1, info1) in enumerate(parsed_networks):
            for j, (net2, info2) in enumerate(parsed_networks[i+1:], i+1):
                # Skip if networks are from the same host and interface
                if (info1.get('hostname') == info2.get('hostname') and 
                    info1.get('interface') == info2.get('interface')):
                    continue
                    
                # Check for overlap
                if net1.overlaps(net2):
                    collision = {
                        'network1': {
                            'hostname': info1.get('hostname', 'unknown'),
                            'pod_name': info1.get('pod_name', 'unknown'),
                            'pod_namespace': info1.get('pod_namespace', 'unknown'),
                            'interface': info1.get('interface', 'unknown'),
                            'network': info1.get('network', 'unknown'),
                        },
                        'network2': {
                            'hostname': info2.get('hostname', 'unknown'),
                            'pod_name': info2.get('pod_name', 'unknown'),
                            'pod_namespace': info2.get('pod_namespace', 'unknown'),
                            'interface': info2.get('interface', 'unknown'),
                            'network': info2.get('network', 'unknown'),
                        },
                        'type': net_type,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'cluster_name': ENV_CONFIG['CLUSTER_NAME']
                    }
                    collisions.append(collision)
                    logger.warning(f"Collision detected between {info1.get('network')} ({info1.get('hostname')}:{info1.get('interface')}) and {info2.get('network')} ({info2.get('hostname')}:{info2.get('interface')})")
    
    logger.info(f"Found {len(collisions)} IP network collisions")
    return collisions


def generate_collision_report(collisions: List[Dict]) -> str:
    """
    Generate a human-readable report of IP network collisions.
    
    Args:
        collisions: List of collision dictionaries
        
    Returns:
        Formatted report as a string
    """
    if not collisions:
        return "No IP network collisions detected."
        
    report = []
    report.append(f"IP NETWORK COLLISION REPORT - {ENV_CONFIG['CLUSTER_NAME']}")
    report.append(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total collisions detected: {len(collisions)}")
    report.append("\n" + "="*50 + "\n")
    
    for i, collision in enumerate(collisions, 1):
        report.append(f"Collision #{i} ({collision['type']})")
        report.append(f"  Network 1: {collision['network1']['network']}")
        report.append(f"    - Host: {collision['network1']['hostname']}")
        report.append(f"    - Pod: {collision['network1']['pod_name']}")
        report.append(f"    - Namespace: {collision['network1']['pod_namespace']}")
        report.append(f"    - Interface: {collision['network1']['interface']}")
        report.append(f"  Network 2: {collision['network2']['network']}")
        report.append(f"    - Host: {collision['network2']['hostname']}")
        report.append(f"    - Pod: {collision['network2']['pod_name']}")
        report.append(f"    - Namespace: {collision['network2']['pod_namespace']}")
        report.append(f"    - Interface: {collision['network2']['interface']}")
        report.append("\n" + "-"*40 + "\n")
    
    return "\n".join(report)


def generate_collision_html_report(collisions: List[Dict]) -> str:
    """
    Generate an HTML report of IP network collisions.
    
    Args:
        collisions: List of collision dictionaries
        
    Returns:
        HTML-formatted report as a string
    """
    if not collisions:
        return "<html><body><h2>No IP network collisions detected.</h2></body></html>"
        
    html = ["<html><body>"]
    html.append(f"<h1>IP NETWORK COLLISION REPORT - {ENV_CONFIG['CLUSTER_NAME']}</h1>")
    html.append(f"<p><strong>Generated at:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
    html.append(f"<p><strong>Total collisions detected:</strong> {len(collisions)}</p>")
    html.append("<hr>")
    
    for i, collision in enumerate(collisions, 1):
        html.append(f"<h2>Collision #{i} ({collision['type']})</h2>")
        html.append("<table border='1' cellpadding='5' style='border-collapse: collapse; width: 80%;'>")
        
        # Table header
        html.append("<tr style='background-color: #f2f2f2;'>")
        html.append("<th></th><th>Network 1</th><th>Network 2</th>")
        html.append("</tr>")
        
        # Network address
        html.append("<tr>")
        html.append("<td><strong>Network</strong></td>")
        html.append(f"<td>{collision['network1']['network']}</td>")
        html.append(f"<td>{collision['network2']['network']}</td>")
        html.append("</tr>")
        
        # Host
        html.append("<tr>")
        html.append("<td><strong>Host</strong></td>")
        html.append(f"<td>{collision['network1']['hostname']}</td>")
        html.append(f"<td>{collision['network2']['hostname']}</td>")
        html.append("</tr>")
        
        # Pod
        html.append("<tr>")
        html.append("<td><strong>Pod</strong></td>")
        html.append(f"<td>{collision['network1']['pod_name']}</td>")
        html.append(f"<td>{collision['network2']['pod_name']}</td>")
        html.append("</tr>")
        
        # Namespace
        html.append("<tr>")
        html.append("<td><strong>Namespace</strong></td>")
        html.append(f"<td>{collision['network1']['pod_namespace']}</td>")
        html.append(f"<td>{collision['network2']['pod_namespace']}</td>")
        html.append("</tr>")
        
        # Interface
        html.append("<tr>")
        html.append("<td><strong>Interface</strong></td>")
        html.append(f"<td>{collision['network1']['interface']}</td>")
        html.append(f"<td>{collision['network2']['interface']}</td>")
        html.append("</tr>")
        
        html.append("</table>")
        html.append("<hr>")
    
    html.append("</body></html>")
    return "".join(html)


def notify_collisions(collisions: List[Dict]) -> None:
    """
    Send email notifications about detected IP network collisions
    if they exceed the notification threshold.
    
    Args:
        collisions: List of collision dictionaries
    """
    if not collisions or len(collisions) < ENV_CONFIG['NOTIFICATION_THRESHOLD']:
        logger.info(f"No notifications sent: {len(collisions)} collisions is below threshold of {ENV_CONFIG['NOTIFICATION_THRESHOLD']}")
        return
        
    # Generate reports
    text_report = generate_collision_report(collisions)
    html_report = generate_collision_html_report(collisions)
    
    # Send notification email
    subject = f"[ALERT] {len(collisions)} IP Network Collisions Detected in {ENV_CONFIG['CLUSTER_NAME']}"
    
    # Attempt to send HTML email first
    html_success = send_email(subject, html_report, is_html=True)
    
    # If HTML email fails, try plain text
    if not html_success:
        send_email(subject, text_report, is_html=False)


def main():
    parser = argparse.ArgumentParser(description='Advanced tool for exploring IP networks in Kubernetes clusters')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--report', action='store_true', help='Report IP networks for this container')
    group.add_argument('--check-collision', metavar='FILE', help='Check for IP network collisions from the provided JSON file')
    parser.add_argument('--output', metavar='FILE', help='Output file (default: stdout)')
    parser.add_argument('--azure-upload', action='store_true', help='Upload results to Azure Blob Storage')
    parser.add_argument('--notify', action='store_true', help='Send email notifications for collisions')
    parser.add_argument('--verbosity', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', 
                        help='Set logging verbosity level')
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity argument
    logger.setLevel(getattr(logging, args.verbosity))
    
    # Initialize Azure integration if needed
    azure = None
    if args.azure_upload:
        azure = AzureIntegration()
        if not azure.initialized:
            logger.warning("Azure integration initialization failed. Azure upload disabled.")
            args.azure_upload = False
    
    # If using Azure Key Vault for email credentials, retrieve them
    if azure and azure.initialized and not ENV_CONFIG['EMAIL_PASSWORD'] and args.notify:
        email_password = azure.get_secret("email-password")
        if email_password:
            ENV_CONFIG['EMAIL_PASSWORD'] = email_password
            logger.info("Retrieved email password from Azure Key Vault")
    
    if args.report:
        # Report mode - output IP network information
        logger.info("Collecting IP network information...")
        networks = get_container_ip_networks()
        output_data = json.dumps(networks, indent=2)
        
        # Save to output file if specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(output_data)
                logger.info(f"Network information saved to {args.output}")
            except Exception as e:
                logger.error(f"Failed to write to output file {args.output}: {e}")
        else:
            print(output_data)
        
        # Upload to Azure if requested
        if args.azure_upload and azure and azure.initialized:
            timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            hostname = socket.gethostname()
            blob_name = f"networks/{ENV_CONFIG['CLUSTER_NAME']}/{hostname}-{timestamp}.json"
            azure.upload_to_blob(networks, blob_name)
            
    elif args.check_collision:
        # Collision check mode
        if not os.path.exists(args.check_collision):
            logger.error(f"Error: File {args.check_collision} does not exist")
            sys.exit(1)
            
        logger.info(f"Checking for IP network collisions in {args.check_collision}...")
        collisions = check_collisions(args.check_collision)
        output_data = json.dumps(collisions, indent=2)
        
        # Save to output file if specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(output_data)
                logger.info(f"Collision information saved to {args.output}")
            except Exception as e:
                logger.error(f"Failed to write to output file {args.output}: {e}")
        else:
            print(output_data)
            
            if not collisions:
                logger.info("No IP network collisions detected.")
            else:
                logger.warning(f"{len(collisions)} IP network collisions detected!")
        
        # Upload to Azure if requested
        if args.azure_upload and azure and azure.initialized:
            timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            blob_name = f"collisions/{ENV_CONFIG['CLUSTER_NAME']}/collisions-{timestamp}.json"
            azure.upload_to_blob(collisions, blob_name)
            
            # Also upload a human-readable report
            if collisions:
                report = generate_collision_report(collisions)
                report_blob_name = f"reports/{ENV_CONFIG['CLUSTER_NAME']}/collision-report-{timestamp}.txt"
                azure.upload_to_blob(report, report_blob_name)
        
        # Send notifications if requested
        if args.notify:
            notify_collisions(collisions)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
        sys.exit(1)