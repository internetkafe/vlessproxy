#!/usr/bin/env bash
set -e

echo "InetProxy: Начало установки..."

if ! command -v unzip &>/dev/null; then
  echo "InetProxy: Установка unzip..."
  sudo apt-get update -qq
  sudo apt-get install -y unzip
fi

if ! command -v go &>/dev/null || [[ "$(go version)" != *"go1.22.3"* ]]; then
  echo "InetProxy: Установка Go 1.22.3..."
  wget -qO go1.22.3.linux-amd64.tar.gz https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
  rm go1.22.3.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  if ! grep -qxF 'export PATH=$PATH:/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  fi
fi

if ! command -v xray &>/dev/null; then
  echo "InetProxy: Установка xray-core..."
  XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest \
             | grep -Po '"tag_name": "\K.*?(?=")')
  wget -qO xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
  unzip -qo xray.zip -d xray_tmp
  sudo mv xray_tmp/xray /usr/local/bin/xray
  sudo chmod +x /usr/local/bin/xray
  rm -rf xray.zip xray_tmp
fi

echo "InetProxy: Инициализация Go модуля..."
export PATH=$PATH:/usr/local/go/bin

if [ ! -f go.mod ]; then
  go mod init inetproxy
fi

echo "InetProxy: Компиляция проекта..."
go mod tidy
go build -o inetproxy .

if [ ! -f .env ]; then
  echo "InetProxy: Создание шаблона .env..."
  cat <<EOF > .env
SUB_FILE="subs.txt"
MAX_PROXIES=50
SOCKS_USER="my_user"
SOCKS_PASS="my_password"
START_PORT=10001
XRAY_BIN="xray"
EOF
fi

if [ ! -f subs.txt ]; then
  echo "InetProxy: Создание шаблона subs.txt..."
  echo "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt" > subs.txt
fi

echo "InetProxy: ✔ Установка завершена!"
echo "InetProxy: Перед запуском отредактируйте файлы .env и subs.txt."
echo "InetProxy: Затем запустите софт командой: ./inetproxy"
