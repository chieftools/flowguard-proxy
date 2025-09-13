# Add repository GPG key
curl -sS https://apt.flowguard.network/keys/51B467ED1A007E3532FA99C0B589D885675B25E5.asc | sudo gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/apt.flowguard.network.gpg

# Add repository to sources
echo "deb https://apt.flowguard.network stable main" | sudo tee /etc/apt/sources.list.d/flowguard.network.list

# Update package list and install packages
sudo apt update
sudo apt install flowguard
