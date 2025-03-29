#!/usr/bin/env python3
import os
import sys
import argparse
import ipaddress
import subprocess
from collections import defaultdict
 
# Environment variables with defaults
CLUSTER_NAMESPACE = os.getenv('CLUSTER_NAMESPACE', 'default')
CONTAINER_NAME_PATTERN = os.getenv('CONTAINER_NAME_PATTERN', '')
OUTPUT_FILE = os.getenv('OUTPUT_FILE', '/tmp/ip-networks-all-containers.txt')
KUBECTL_CMD = os.getenv('KUBECTL_CMD', 'kubectl')
 
def get_local_ip_networks():
    """Get all IP networks configured on the local container"""
    try:
        result = subprocess.run(['ip', '-o', 'addr'], capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()
        
        networks = []
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 4 and parts[2] == 'inet':
                addr = parts[3]
# Handle cases like "192.168.1.1/24" or "192.168.1.1"
                if '/' in addr:
                    network = ipaddress.ip_network(addr, strict=False)
                else:
                    network = ipaddress.ip_network(f"{addr}/32", strict=False)
                networks.append(str(network))
        
        return networks
    except Exception as e:
        print(f"Error getting local IP networks: {e}", file=sys.stderr)
        return []
 
def collect_all_networks(output_file):
    """Collect IP networks from all containers in the cluster"""
    try:
        # Get all pods in the namespace
        cmd = [
            KUBECTL_CMD,
            'get', 'pods',
            '--namespace', CLUSTER_NAMESPACE,
            '--output=jsonpath={.items[*].metadata.name}'
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        pods = result.stdout.split()
        
        with open(output_file, 'w') as f:
            for pod in pods:
                if CONTAINER_NAME_PATTERN and CONTAINER_NAME_PATTERN not in pod:
                    continue
                
                try:
                    # Execute ip-tool in each container (assuming it's available)
                    cmd = [
                        KUBECTL_CMD,
                        'exec', pod,
                        '--namespace', CLUSTER_NAMESPACE,
                        '--', 'ip-tool'
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                    
                    # Write pod name and its networks to the file
                    f.write(f"=== {pod} ===\n")
                    f.write(result.stdout)
                    f.write("\n")
                except subprocess.CalledProcessError as e:
                    print(f"Error executing in pod {pod}: {e}", file=sys.stderr)
                    continue
        
        print(f"All IP networks collected in {output_file}", file=sys.stderr)
    except Exception as e:
        print(f"Error collecting networks: {e}", file=sys.stderr)
        sys.exit(1)
 
def check_collisions(input_file):
    """Check for IP network collisions in the collected data"""
    network_map = defaultdict(list)
    
    try:
        with open(input_file, 'r') as f:
            current_pod = None
            for line in f:
                line = line.strip()
                if line.startswith('===') and line.endswith('==='):
                    current_pod = line[4:-4].strip()
                    continue
                
                if not line or not current_pod:
                    continue
                
                try:
                    network = ipaddress.ip_network(line)
                    network_map[str(network)].append(current_pod)
                except ValueError:
                    continue
        
        # Find collisions (networks used by more than one pod)
        collisions = {net: pods for net, pods in network_map.items() if len(pods) > 1}
        
        if collisions:
            print("IP NETWORK COLLISIONS FOUND:", file=sys.stderr)
            for net, pods in collisions.items():
                print(f"\nNetwork: {net}")
                print("Used by pods:")
                for pod in pods:
                    print(f"  - {pod}")
            sys.exit(1)
        else:
            print("No IP network collisions found.", file=sys.stderr)
            sys.exit(0)
            
    except Exception as e:
        print(f"Error checking collisions: {e}", file=sys.stderr)
        sys.exit(1)
 
def main():
    parser = argparse.ArgumentParser(description='Kubernetes IP Network Collision Checker')
    parser.add_argument('--check-collision', metavar='FILE',
                       help='Check for IP network collisions in the collected output file')