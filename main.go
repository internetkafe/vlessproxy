package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "os/signal"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/joho/godotenv"
)

var (
    activeProxies []map[string]interface{}
    spareProxies  []map[string]interface{}
    xrayCmd       *exec.Cmd
    proxyMutex    sync.Mutex
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
    recheckInterval := 0

    if p := os.Getenv("START_PORT"); p != "" {
        fmt.Sscanf(p, "%d", &startPort)
    }
    if m := os.Getenv("MAX_PROXIES"); m != "" {
        fmt.Sscanf(m, "%d", &maxProxies)
    }
    if r := os.Getenv("RECHECK_INTERVAL"); r != "" {
        fmt.Sscanf(r, "%d", &recheckInterval)
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

    working, spares := w.Run()

    if len(working) == 0 {
        log.Fatal("Живых прокси не найдено.")
    }

    proxyMutex.Lock()
    activeProxies = working
    spareProxies = spares
    proxyMutex.Unlock()

    finalConfig := buildXrayConfig(activeProxies, startPort, socksUser, socksPass)
    finalFile := "final_config.json"
    saveConfig(finalConfig, finalFile)

    serverIP := getPublicIP()

    log.Println("Запуск финального Xray-core с рабочими прокси...")
    xrayCmd = startXrayFinal(finalFile, xrayBin)
    time.Sleep(2 * time.Second)

    printProxies(activeProxies, serverIP, startPort, socksUser, socksPass)

    if recheckInterval > 0 {
        log.Printf("Включена перепроверка каждые %d секунд.", recheckInterval)
        go startMaintenanceLoop(recheckInterval, startPort, socksUser, socksPass, xrayBin, maxProxies, serverIP)
    } else {
        log.Println("Перепроверка отключена (RECHECK_INTERVAL=0).")
    }

    fmt.Println("Нажмите Ctrl+C для остановки.")

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan
    log.Println("\nОстановка...")
}

func printProxies(proxies []map[string]interface{}, serverIP string, startPort int, user, pass string) {
    fmt.Println("\n==========================================")
    fmt.Println("InetProxy: 🚀 Активные прокси:")
    fmt.Printf("Логин: %s | Пароль: %s\n", user, pass)
    fmt.Println("==========================================")
    for i := range proxies {
        fmt.Printf("%s:%d\n", serverIP, startPort+i)
    }
    fmt.Println("==========================================")
}

func startMaintenanceLoop(interval, startPort int, user, pass, bin string, maxProxies int, serverIP string) {
    for {
        time.Sleep(time.Duration(interval) * time.Second)
        log.Println("Запуск перепроверки прокси...")

        proxyMutex.Lock()
        
        status := checkProxiesStatus(activeProxies, startPort, user, pass)
        
        var deadIndices []int
        for i, isAlive := range status {
            if !isAlive {
                deadIndices = append(deadIndices, i)
            }
        }

        if len(deadIndices) > 0 {
            log.Printf("Обнаружено %d мертвых прокси. Ищу живые замены в запасах...", len(deadIndices))
            
            // Ищем живые прокси среди запасов
            liveSpares, remainingSpares := verifySpareProxies(spareProxies, len(deadIndices), user, pass, bin)
            spareProxies = remainingSpares

            replacedCount := 0
            for _, idx := range deadIndices {
                if len(liveSpares) > 0 {
                    // Заменяем мертвый прокси на живой из запасов на ТОТ ЖЕ САМЫЙ порт
                    activeProxies[idx] = liveSpares[0]
                    liveSpares = liveSpares[1:]
                    replacedCount++
                }
            }

            if replacedCount > 0 {
                log.Printf("Успешно заменено %d прокси. Перезапуск Xray...", replacedCount)
                
                if xrayCmd != nil && xrayCmd.Process != nil {
                    xrayCmd.Process.Kill()
                    xrayCmd.Wait()
                }

                finalConfig := buildXrayConfig(activeProxies, startPort, user, pass)
                saveConfig(finalConfig, "final_config.json")
                xrayCmd = startXrayFinal("final_config.json", bin)
                time.Sleep(2 * time.Second)

                printProxies(activeProxies, serverIP, startPort, user, pass)
            } else {
                log.Println("Живых прокси в запасах не найдено для замены.")
            }
        } else {
            log.Println("Все активные прокси живы.")
        }

        proxyMutex.Unlock()
    }
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
