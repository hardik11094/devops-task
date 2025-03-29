# Use a lightweight Python base image
FROM python:3.9-slim
 
# Set environment variables
ENV CLUSTER_NAMESPACE=default \
    CONTAINER_NAME_PATTERN="" \
    OUTPUT_FILE="/data/ip-networks-all-containers.txt" \
    KUBECTL_CMD="kubectl" \
    MODE="default"
 
# Install required system packages
RUN apt-get update && apt-get install -y \
    iproute2 \
    sudo \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
 
# Install kubectl (specific version for reproducibility)
ENV KUBECTL_VERSION=v1.28.4
RUN curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/ \
    && kubectl version --client
 
# Create data directory for output files
RUN mkdir -p /data && chmod 777 /data
 
# Copy the script and make it executable
COPY ip_tool.py /usr/local/bin/
RUN chmod +x /usr/local/bin/ip-tool
 
# Create entrypoint script
COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh
 
# Create a non-root user and switch to it
RUN useradd -m ipchecker \
    && chown -R ipchecker:ipchecker /usr/local/bin/ip-tool \
    && chown -R ipchecker:ipchecker /data
USER ipchecker
 
# Set the working directory
WORKDIR /home/ipchecker
 
ENTRYPOINT ["entrypoint.sh"]