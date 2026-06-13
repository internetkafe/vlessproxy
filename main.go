package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/joho/godotenv"
)

func main() {
    log.SetPrefix("InetProxy: ")

    if err := godotenv.Load(); err != nil {
        log.Println("Файл .env не найден, используем переменные окружения")
    }

    subFile := getEnv("SUB_FILE", "subs.txt")
    socksUser := os.Getenv("SOCKS_USER")
    socksPass := os.Getenv("SOCKS_PASS")
    xrayBin := getEnv("XRAY_BIN", "xray")
    startPort := 10001
    maxProxies := 0

    if p := os.Getenv("START_PORT"); p != "" {
        fmt.Sscanf(p, "%d", &startPort)
    }
    if m := os.Getenv("MAX_PROXIES"); m != "" {
        fmt.Sscanf(m, "%d", &maxProxies)
    }

    if socksUser == "" || socksPass == "" {
        log.Fatal("Не заполнены обязательные переменные в .env (SOCKS_USER, SOCKS_PASS)")
    }

    w := &Worker{
        SubFile:    subFile,
        SocksUser:  socksUser,
        SocksPass:  socksPass,
        StartPort:  startPort,
        MaxProxies: maxProxies,
        XrayBin:    xrayBin,
    }

    workingOutbounds := w.Run()

    if len(workingOutbounds) == 0 {
        log.Fatal("Живых прокси не найдено.")
    }

    if maxProxies > 0 && len(workingOutbounds) > maxProxies {
        workingOutbounds = workingOutbounds[:maxProxies]
    }

    finalConfig := buildXrayConfig(workingOutbounds, startPort, socksUser, socksPass)
    finalFile := "final_config.json"
    saveConfig(finalConfig, finalFile)

    serverIP := getPublicIP()

    log.Println("Запуск финального Xray-core с рабочими прокси...")
    go startXrayFinal(finalFile, xrayBin)
    time.Sleep(2 * time.Second)

    fmt.Println("\n==========================================")
    fmt.Println("InetProxy: 🚀 Запуск успешен!")
    fmt.Printf("Логин: %s | Пароль: %s\n", socksUser, socksPass)
    fmt.Println("Список рабочих SOCKS5 прокси (IP:PORT):")
    fmt.Println("==========================================")
    for i := range workingOutbounds {
        fmt.Printf("%s:%d\n", serverIP, startPort+i)
    }
    fmt.Println("==========================================")
    fmt.Println("Нажмите Ctrl+C для остановки.")

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan
    log.Println("\nОстановка...")
}

func getPublicIP() string {
    if ip := os.Getenv("VDS_IP"); ip != "" {
        return ip
    }
    resp, err := http.Get("https://api.ipify.org")
    if err == nil {
        defer resp.Body.Close()
        ipBytes, _ := io.ReadAll(resp.Body)
        if ip := strings.TrimSpace(string(ipBytes)); ip != "" {
            return ip
        }
    }
    return "0.0.0.0"
}

func getEnv(key, fallback string) string {
    if val, ok := os.LookupEnv(key); ok {
        return val
    }
    return fallback
}
