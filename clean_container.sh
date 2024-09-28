#!/bin/bash

echo "Cleaning up Docker containers..."

# Stop all running Docker containers
docker stop $(docker ps -q)

# Remove all Docker containers
docker rm $(docker ps -a -q)

# Remove all Docker images (optional)
# Uncomment the next line if you also want to remove all Docker images
# docker rmi $(docker images -q)

echo "Docker containers cleaned up."

echo "Cleaning up containerd containers..."

# Stop all running containerd tasks
sudo ctr task kill --all

# Remove all containerd containers
sudo ctr container rm $(sudo ctr container list -q)

# Remove all containerd images (optional)
# Uncomment the next line if you also want to remove all containerd images
# sudo ctr image rm $(sudo ctr image list -q)

echo "containerd containers cleaned up."

echo "Cleanup complete."
