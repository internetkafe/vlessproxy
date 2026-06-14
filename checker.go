package main
import (
    "context"
    "fmt"
    "log"
    "net"
    "net/http"
    "time"
    "golang.org/x/net/proxy"
)
func checkSingleProxy(port int, user, pass string) bool {
    auth := &proxy.Auth{User: user, Password: pass}
    dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), auth,
&net.Dialer{Timeout: 8 * time.Second}) // Было 5
    if err != nil {
        return false
    }
    client := &http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                return dialer.Dial(network, addr)
            },
        },
        Timeout: 15 * time.Second, // Было 10
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
// ИСПРАВЛЕНО: Теперь функция циклично проходит по всем запасам батчами, пока не найдет нужное количество
func verifySpareProxies(proxies []map[string]interface{}, countNeeded int, socksUser, socksPass, xrayBin string) (live []map[string]interface{}, remaining []map[string]interface{}) {
    if len(proxies) == 0 || countNeeded == 0 {
        return nil, proxies
    }
    var liveFound []map[string]interface{}
    batchSize := 150
    currentIndex := 0
    // Гоняем по запасам батчами, пока не наберем нужное число живых или пока запасы не кончатся
    for currentIndex < len(proxies) && len(liveFound) < countNeeded {
        neededNow := countNeeded - len(liveFound)
        end := currentIndex + batchSize
        if end > len(proxies) {
            end = len(proxies)
        }
        batch := proxies[currentIndex:end]
        log.Printf("-> Проверка запасов батч %d - %d из %d (нужно еще найти: %d)...", currentIndex+1, end, len(proxies), neededNow)
        tempStartPort := 60000
        evalConfig := buildXrayConfig(batch, tempStartPort, socksUser, socksPass)
        evalFile := "spare_eval_config.json"
        saveConfig(evalConfig, evalFile)
        evalCmd := startXrayBackground(evalFile, xrayBin)
        time.Sleep(3 * time.Second)
        liveInBatch := checkProxiesParallel(batch, tempStartPort, socksUser, socksPass, neededNow)
        if evalCmd != nil && evalCmd.Process != nil {
            evalCmd.Process.Kill()
            evalCmd.Wait()
        }
        if len(liveInBatch) > 0 {
            log.Printf("   Найдено живых в запасах: %d", len(liveInBatch))
            liveFound = append(liveFound, liveInBatch...)
        }
        currentIndex = end
    }
    // Возвращаем живых и неразобранный остаток списка
    return liveFound, proxies[currentIndex:]
}
