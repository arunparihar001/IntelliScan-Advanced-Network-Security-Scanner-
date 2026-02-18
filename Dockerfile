FROM ubuntu:22.04

# Install Nmap and required dependencies
RUN apt-get update && \
    apt-get install -y nmap && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -s /bin/bash nmapuser

# Switch to non-root user
USER nmapuser

# Set working directory
WORKDIR /home/nmapuser

# Command to run when container starts
ENTRYPOINT ["nmap"] 