#!/usr/bin/env bash
set -e

echo "InetProxy: Начало установки..."

# 1. Установка системных зависимостей (curl для скриптов, unzip на всякий случай)
echo "InetProxy: Проверка системных зависимостей..."
sudo apt-get update -qq
sudo apt-get install -y curl unzip

# 2. Установка Go (только если не установлен)
if ! command -v go &>/dev/null; then
  echo "InetProxy: Go не найден. Установка Go 1.22.5..."
  wget -qO go1.22.5.linux-amd64.tar.gz https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
  rm go1.22.5.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  if ! grep -qxF 'export PATH=$PATH:/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  fi
else
  echo "InetProxy: Go уже установлен ($(go version | awk '{print $3}')). Используем его."
fi

# 3. Установка Xray-core через ОФИЦИАЛЬНЫЙ скрипт установки
if ! command -v xray &>/dev/null; then
  echo "InetProxy: Установка xray-core через официальный установщик..."
  # Скачиваем и запускаем официальный скрипт установки релизной версии
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
else
  echo "InetProxy: Xray-core уже установлен."
fi

# 4. Инициализация Go модуля и компиляция проекта
export PATH=$PATH:/usr/local/go/bin

if [ ! -f go.mod ]; then
  echo "InetProxy: Файл go.mod не найден. Инициализация нового Go модуля..."
  go mod init inetproxy
else
  echo "InetProxy: Найден существующий go.mod. Пропуск инициализации."
fi

echo "InetProxy: Установка зависимостей и компиляция проекта..."
go mod tidy
go build -o inetproxy .

# 5. Создание шаблонов конфигурации, если их нет
if [ ! -f .env ]; then
  echo "InetProxy: Создание шаблона .env..."
  cat <<EOF > .env
SUB_FILE="subs.txt"
MAX_PROXIES=50
SOCKS_USER="my_user"
SOCKS_PASS="my_password"
START_PORT=10001
XRAY_BIN="xray"
# Интервал перепроверки прокси в секундах (0 = отключено)
RECHECK_INTERVAL=60
EOF
else
  echo "InetProxy: Файл .env уже существует. Пропуск перезаписи."
fi

if [ ! -f subs.txt ]; then
  echo "InetProxy: Создание шаблона subs.txt..."
  echo "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt" > subs.txt
else
  echo "InetProxy: Файл subs.txt уже существует. Пропуск перезаписи."
fi

echo "InetProxy: ✔ Установка и компиляция завершены!"
echo "InetProxy: Перед запуском отредактируйте файлы .env и subs.txt под свои нужды."
echo "InetProxy: Затем запустите софт командой: ./inetproxy"
