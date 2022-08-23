sudo apt-get update
sudo apt-get install -y gnupg2 curl software-properties-common
curl -O https://releases.algorand.com/key.pub
sudo apt-key add key.pub
sudo add-apt-repository "deb [arch=amd64] https://releases.algorand.com/deb/ stable main"
sudo apt-get update
sudo apt-get install -y algorand-devtools
sudo systemctl stop algorand
sudo apt update
sudo apt install screen -y
sudo apt install unzip -y
sudo apt install z3 -y
sudo apt install libpq-dev python3-dev -y
pip3 install z3-solver
pip3 install psycopg2
pip3 install py-algorand-sdk