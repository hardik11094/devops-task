# devops-task



"""
ip-tool - A comprehensive utility to explore IP range collisions in Kubernetes clusters
with Azure integration for reporting and monitoring.

This script offers the following functionality:
1. Report configured IP networks for the current container
2. Check for collisions between IP networks across the cluster
3. Export network information to Azure Storage
4. Send email notifications for detected collisions
5. Integration with Azure Key Vault for secure credentials
"""


Note- 

Add below env variables as Pipeline variables value when you run pipeline to build and publish docker image 

OR 

You can pass them directly in the deployment yaml as well.

# Set environment variables
ENV EMAIL_SENDER=""
ENV EMAIL_RECIPIENTS=""
ENV EMAIL_PASSWORD=""
ENV SMTP_SERVER=""
ENV AZURE_CLIENT_ID=""
ENV AZURE_CLIENT_SECRET=""
ENV AZURE_TENANT_ID=""
ENV AZURE_KEYVAULT_NAME=""
ENV AZURE_STORAGE_ACCOUNT=""
ENV AZURE_STORAGE_CONTAINER="ip-tool-data"
ENV CLUSTER_NAME="unknown-cluster"
ENV NOTIFICATION_THRESHOLD=1
ENV LOG_FILE_PATH="/var/log/ip-tool.log"



Note - 

To schedule your Kubernetes deployment to trigger every day at 11 AM IST, you can use a Kubernetes CronJob. Here's an example of how you can set this up:


apiVersion: batch/v1
kind: CronJob
metadata:
  name: ip-tool-cronjob
spec:
  schedule: "30 5 * * *" # This is 11 AM IST (IST is UTC+5:30)
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: ip-tool
            image: docker.my.registry/devops-task/ip-tool:latest
            env:
            - name: EMAIL_SENDER
              value: "your_email@example.com"
            - name: EMAIL_PASSWORD
              value: "your_password"
            - name: SMTP_SERVER
              value: "smtp.example.com"
            - name: AZURE_CLIENT_ID
              value: "your_azure_client_id"
            - name: AZURE_CLIENT_SECRET
              value: "your_azure_client_secret"
            - name: AZURE_TENANT_ID
              value: "your_azure_tenant_id"
            - name: AZURE_KEYVAULT_NAME
              value: "your_keyvault_name"
            - name: AZURE_STORAGE_ACCOUNT
              value: "your_storage_account"
            - name: AZURE_STORAGE_CONTAINER
              value: "ip-tool-data"
            - name: CLUSTER_NAME
              value: "your_cluster_name"
            - name: NOTIFICATION_THRESHOLD
              value: "1"
            - name: LOG_FILE_PATH
              value: "/var/log/ip-tool.log"
          restartPolicy: OnFailure