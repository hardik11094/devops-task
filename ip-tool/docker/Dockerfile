# Use an optimized Python 3.8 image
FROM python:3.8-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file (if you have one)
COPY requirements.txt .

# Install the required packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Run the script
CMD ["python", "ip-tool.py"]