# devops-task


# Kubernetes IP Collision Checker
 
A tool to detect IP range conflicts in Kubernetes clusters.
 
## Key Components
 
- **`ip-tool`**: Python script that:
  - Reports container IP networks (default mode)
  - Checks for collisions across clusters (`--check-collision`)
 
- **Dockerized**:
  - Lightweight Python image
  - Supports 3 modes via `MODE` env var:
    - `default`: Report local IPs
    - `collection`: Gather cluster IPs
    - `check`: Detect collisions
 
- **Azure Pipeline**:
  - Builds Docker image
  - Pushes to ACR
  - Deploys to Kubernetes