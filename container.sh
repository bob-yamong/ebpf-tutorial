echo "Installing Docker"

# Install Docker
sudo apt-get update
sudo apt-get install -y docker.io

# Add user to docker group
sudo groupadd docker
sudo usermod -aG docker $USER

# Restart Docker
sudo systemctl restart docker

# Install docker-compose
sudo apt-get install -y docker-compose

# Run docker-compose
docker-compose up -d

echo "Docker installed successfully"

echo "Installing Containerd"
# Install containerd
sudo apt-get install -y containerd

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml

sudo systemctl start containerd

# Pull the Ubuntu image
sudo ctr image pull docker.io/library/ubuntu:latest

# Run the Ubuntu container and keep it alive with a long-running process
sudo ctr run --rm -t docker.io/library/ubuntu:latest ubuntu-containerd /bin/sh -c "while :; do sleep 3600; done" &

echo "Containerd container created and running in the background."
