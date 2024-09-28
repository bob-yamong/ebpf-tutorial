# Install Docker
sudo apt-get update
sudo apt-get install docker.io

# Add user to docker group
sudo groupadd docker
sudo usermod -aG docker $USER

# restart docker
sudo systemctl restart docker

# Install docker-compose
sudo apt-get install docker-compose

# Run docker-compose
docker-compose up -d


# Install containerd
sudo apt-get install containerd

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml

sudo ctr image pull docker.io/library/ubuntu:latest
sudo ctr run docker.io/library/ubuntu:latest ubuntu-containerd

# Install cri-o
sudo apt-get install -y software-properties-common

# CRI-O 저장소 추가
OS="xUbuntu_22.04"
VERSION="1.26"
echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
echo "deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.list
curl -L https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:$VERSION/$OS/Release.key | sudo apt-key add -
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | sudo apt-key add -

# CRI-O 설치
sudo apt-get update
sudo apt-get install -y cri-o cri-o-runc

# CRI-O 활성화
sudo systemctl daemon-reload
sudo systemctl enable crio
sudo systemctl start crio

# CRI-O 상태 확인 -> running이어야 함
sudo systemctl status crio