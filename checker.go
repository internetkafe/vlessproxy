package main

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "time"

    "golang.org/x/net/proxy"
)

func checkSingleProxy(port int, user, pass string) bool {
    auth := &proxy.Auth{User: user, Password: pass}
    dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), auth, &net.Dialer{Timeout: 5 * time.Second})
    if err != nil {
        return false
    }

    client := &http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                return dialer.Dial(network, addr)
            },
        },
        Timeout: 10 * time.Second,
    }

    resp, err := client.Get("http://www.gstatic.com/generate_204")
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    return resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK
}

func checkProxiesParallel(outbounds []map[string]interface{}, startPort int, user, pass string, needed int) []map[string]interface{} {
    type result struct {
        index   int
        isAlive bool
    }
    resultsChan := make(chan result, len(outbounds))
    var workingOutbounds []map[string]interface{}

    for i := range outbounds {
        go func(idx int) {
            resultsChan <- result{index: idx, isAlive: checkSingleProxy(startPort+idx, user, pass)}
        }(i)
    }

    checked := 0
    for res := range resultsChan {
        checked++
        if res.isAlive {
            workingOutbounds = append(workingOutbounds, outbounds[res.index])
        }
        if needed > 0 && len(workingOutbounds) >= needed {
            break
        }
        if checked == len(outbounds) {
            break
        }
    }
    return workingOutbounds
}

func checkProxiesStatus(outbounds []map[string]interface{}, startPort int, user, pass string) map[int]bool {
    type result struct {
        index   int
        isAlive bool
    }
    resultsChan := make(chan result, len(outbounds))
    status := make(map[int]bool)

    for i := range outbounds {
        go func(idx int) {
            resultsChan <- result{index: idx, isAlive: checkSingleProxy(startPort+idx, user, pass)}
        }(i)
    }

    for i := 0; i < len(outbounds); i++ {
        res := <-resultsChan
        status[res.index] = res.isAlive
    }
    return status
}

// НОВАЯ ФУНКЦИЯ: Проверка запасных прокси перед заменой
func verifySpareProxies(proxies []map[string]interface{}, countNeeded int, socksUser, socksPass, xrayBin string) (live []map[string]interface{}, remaining []map[string]interface{}) {
    if len(proxies) == 0 || countNeeded == 0 {
        return nil, proxies
    }

    // Берем с запасом, т.к. многие могут быть мертвы
    limit := countNeeded * 3
    if limit > len(proxies) {
        limit = len(proxies)
    }

    batch := proxies[:limit]
    // Оставшиеся запасы возвращаем обратно
    remaining = proxies[limit:]

    // Используем временные порты 60000+, чтобы не конфликтовать с рабочими 10001+
    tempStartPort := 60000

    evalConfig := buildXrayConfig(batch, tempStartPort, socksUser, socksPass)
    evalFile := "spare_eval_config.json"
    saveConfig(evalConfig, evalFile)

    evalCmd := startXrayBackground(evalFile, xrayBin)
    time.Sleep(3 * time.Second)

    // Проверяем, кто из запасов живой
    live = checkProxiesParallel(batch, tempStartPort, socksUser, socksPass, countNeeded)

    if evalCmd != nil && evalCmd.Process != nil {
        evalCmd.Process.Kill()
        evalCmd.Wait()
    }

    return live, remaining
}
