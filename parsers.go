 package main

import (
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net"
    "net/url"
    "strings"
)

type VMessLink struct {
    V    string `json:"v"`
    Ps   string `json:"ps"`
    Add  string `json:"add"`
    Port string `json:"port"`
    Id   string `json:"id"`
    Aid  string `json:"aid"`
    Scy  string `json:"scy"`
    Net  string `json:"net"`
    Type string `json:"type"`
    Host string `json:"host"`
    Path string `json:"path"`
    Tls  string `json:"tls"`
    Sni  string `json:"sni"`
    Alpn string `json:"alpn"`
    Fp   string `json:"fp"`
}


func getParam(params url.Values, key, fallback string) string {
    if val, ok := params[key]; ok && len(val) > 0 && val[0] != "" {
        return val[0]
    }
    return fallback
}

func getBoolParam(params url.Values, key string, fallback bool) bool {
    val := getParam(params, key, "")
    if val == "1" || strings.ToLower(val) == "true" {
        return true
    }
    if val == "0" || strings.ToLower(val) == "false" {
        return false
    }
    return fallback
}

func getAlpnParam(params url.Values, key string) []string {
    val := getParam(params, key, "")
    if val == "" {
        return nil
    }
    return strings.Split(val, ",")
}

func decodeBase64(s string) ([]byte, error) {
    s = strings.ReplaceAll(s, "\n", "")
    s = strings.ReplaceAll(s, "\r", "")
    s = strings.ReplaceAll(s, " ", "")
    s = strings.TrimSpace(s)

    if len(s)%4 != 0 {
        s += strings.Repeat("=", 4-len(s)%4)
    }

    decoded, err := base64.StdEncoding.DecodeString(s)
    if err == nil {
        return decoded, nil
    }

    decoded, err = base64.URLEncoding.DecodeString(s)
    if err == nil {
        return decoded, nil
    }

    decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
    if err == nil {
        return decoded, nil
    }

    return nil, fmt.Errorf("base64 decode failed")
}

func parseVLESS(uri string) (map[string]interface{}, error) {
    parsed, err := url.Parse(uri)
    if err != nil {
        return nil, err
    }
    params := parsed.Query()
    uuid := parsed.User.Username()
    address := parsed.Hostname()
    portStr := parsed.Port()

    var portInt uint16
    fmt.Sscanf(portStr, "%d", &portInt)

    netType := getParam(params, "type", "tcp")
    secType := getParam(params, "security", "none")
    encryption := getParam(params, "encryption", "none")

    outbound := map[string]interface{}{
        "protocol": "vless",
        "settings": map[string]interface{}{
            "vnext": []map[string]interface{}{{
                "address": address, "port": portInt,
                "users": []map[string]interface{}{{"id": uuid, "encryption": encryption}},
            }},
        },
        "streamSettings": map[string]interface{}{
            "network":  netType,
            "security": secType,
        },
    }

    ss := outbound["streamSettings"].(map[string]interface{})

    switch netType {
    case "ws":
        ws := map[string]interface{}{"path": getParam(params, "path", "/")}
        if host := getParam(params, "host", ""); host != "" {
            ws["host"] = host
        }
        ss["wsSettings"] = ws
    case "grpc":
        grpc := map[string]interface{}{}
        if sn := getParam(params, "serviceName", ""); sn != "" {
            grpc["serviceName"] = sn
        }
        if auth := getParam(params, "authority", ""); auth != "" {
            grpc["authority"] = auth
        }
        if mode := getParam(params, "mode", ""); mode == "multi" {
            grpc["multiMode"] = true
        }
        ss["grpcSettings"] = grpc
    case "xhttp", "splithttp":
        xhttp := map[string]interface{}{"path": getParam(params, "path", "/")}
        if host := getParam(params, "host", ""); host != "" {
            xhttp["host"] = host
        }
        if mode := getParam(params, "mode", ""); mode != "" {
            xhttp["mode"] = mode
        }
        ss["xhttpSettings"] = xhttp
    }

    if secType == "tls" {
        tls := map[string]interface{}{
            "serverName":    getParam(params, "sni", ""),
            "allowInsecure": getBoolParam(params, "allowInsecure", false),
        }
        if alpn := getAlpnParam(params, "alpn"); alpn != nil {
            tls["alpn"] = alpn
        }
        if fp := getParam(params, "fp", ""); fp != "" {
            tls["fingerprint"] = fp
        }
        ss["tlsSettings"] = tls
    } else if secType == "reality" {
        pbk := getParam(params, "pbk", "")
        if pbk == "" {
            return nil, fmt.Errorf("no pbk for reality")
        }
        reality := map[string]interface{}{
            "serverName":  getParam(params, "sni", ""),
            "fingerprint": getParam(params, "fp", "chrome"),
            "publicKey":   pbk,
            "shortId":     getParam(params, "sid", ""),
            "spiderX":     "",
        }
        ss["realitySettings"] = reality
    }

    return outbound, nil
}

func parseVMess(uri string) (map[string]interface{}, error) {
    if !strings.HasPrefix(uri, "vmess://") {
        return nil, fmt.Errorf("not vmess")
    }
    b64 := strings.TrimPrefix(uri, "vmess://")

    decoded, err := decodeBase64(b64)
    if err != nil {
        return nil, err
    }

    var v VMessLink
    if err := json.Unmarshal(decoded, &v); err != nil {
        return nil, err
    }

    var portInt uint16
    fmt.Sscanf(v.Port, "%d", &portInt)
    aid := 0
    fmt.Sscanf(v.Aid, "%d", &aid)

    outbound := map[string]interface{}{
        "protocol": "vmess",
        "settings": map[string]interface{}{
            "vnext": []map[string]interface{}{{
                "address": v.Add, "port": portInt,
                "users": []map[string]interface{}{{"id": v.Id, "alterId": aid, "security": v.Scy}},
            }},
        },
        "streamSettings": map[string]interface{}{
            "network":  v.Net,
            "security": v.Tls,
        },
    }

    ss := outbound["streamSettings"].(map[string]interface{})

    switch v.Net {
    case "ws":
        ws := map[string]interface{}{"path": v.Path}
        if v.Host != "" {
            ws["host"] = v.Host
        }
        ss["wsSettings"] = ws
    case "grpc":
        grpc := map[string]interface{}{"serviceName": v.Path}
        if v.Host != "" {
            grpc["authority"] = v.Host
        }
        ss["grpcSettings"] = grpc
    case "xhttp", "splithttp":
        xhttp := map[string]interface{}{"path": v.Path}
        if v.Host != "" {
            xhttp["host"] = v.Host
        }
        ss["xhttpSettings"] = xhttp
    }

    if v.Tls == "tls" {
        tls := map[string]interface{}{
            "serverName":    v.Sni,
            "allowInsecure": false,
        }
        if v.Alpn != "" {
            tls["alpn"] = strings.Split(v.Alpn, ",")
        }
        if v.Fp != "" {
            tls["fingerprint"] = v.Fp
        }
        ss["tlsSettings"] = tls
    }

    return outbound, nil
}

func parseShadowsocks(uri string) (map[string]interface{}, error) {
    if !strings.HasPrefix(uri, "ss://") {
        return nil, fmt.Errorf("not ss")
    }

    uriWithoutScheme := strings.TrimPrefix(uri, "ss://")
    parts := strings.SplitN(uriWithoutScheme, "#", 2)
    mainPart := parts[0]

    var method, password, host, portStr string
    var decoded []byte
    var err error 

    if strings.Contains(mainPart, "@") {
        sip002Parts := strings.SplitN(mainPart, "@", 2)
        if len(sip002Parts) != 2 {
            return nil, fmt.Errorf("invalid ss sip002 format")
        }

        decoded, err = decodeBase64(sip002Parts[0]) // <--- Используем =
        if err != nil {
            return nil, fmt.Errorf("invalid ss sip002 base64: %v", err)
        }
        credParts := strings.SplitN(string(decoded), ":", 2)
        if len(credParts) != 2 {
            return nil, fmt.Errorf("invalid ss sip002 credentials")
        }
        method = credParts[0]
        password = credParts[1]
        hostPortStr := sip002Parts[1]

        host, portStr, err = net.SplitHostPort(hostPortStr)
        if err != nil {
            return nil, fmt.Errorf("invalid ss sip002 host:port: %v", err)
        }
    } else {
        decoded, err = decodeBase64(mainPart) // <--- Используем =
        if err != nil {
            return nil, fmt.Errorf("invalid ss legacy base64: %v", err)
        }
        decodedStr := string(decoded)

        atIdx := strings.LastIndex(decodedStr, "@")
        if atIdx == -1 {
            return nil, fmt.Errorf("invalid ss legacy format: no @")
        }

        credPart := decodedStr[:atIdx]
        hostPortStr := decodedStr[atIdx+1:]

        credParts := strings.SplitN(credPart, ":", 2)
        if len(credParts) != 2 {
            return nil, fmt.Errorf("invalid ss legacy credentials")
        }
        method = credParts[0]
        password = credParts[1]

        host, portStr, err = net.SplitHostPort(hostPortStr)
        if err != nil {
            return nil, fmt.Errorf("invalid ss legacy host:port: %v", err)
        }
    }

    var portInt uint16
    _, err = fmt.Sscanf(portStr, "%d", &portInt) // <--- Теперь err видна
    if err != nil || portInt == 0 {
        return nil, fmt.Errorf("invalid ss port: %s", portStr)
    }

    return map[string]interface{}{
        "protocol": "shadowsocks",
        "settings": map[string]interface{}{
            "servers": []map[string]interface{}{{
                "address":  host,
                "port":     portInt,
                "method":   method,
                "password": password,
            }},
        },
    }, nil
}

func parseTrojan(uri string) (map[string]interface{}, error) {
    parsed, err := url.Parse(uri)
    if err != nil {
        return nil, err
    }
    password := parsed.User.Username()
    address := parsed.Hostname()
    portStr := parsed.Port()
    params := parsed.Query()
    var portInt uint16
    fmt.Sscanf(portStr, "%d", &portInt)

    netType := getParam(params, "type", "tcp")
    secType := getParam(params, "security", "tls")
    encryption := getParam(params, "encryption", "")

    outbound := map[string]interface{}{
        "protocol": "trojan",
        "settings": map[string]interface{}{
            "servers": []map[string]interface{}{{"address": address, "port": portInt, "password": password}},
        },
        "streamSettings": map[string]interface{}{
            "network":  netType,
            "security": secType,
        },
    }

    ss := outbound["streamSettings"].(map[string]interface{})

    switch netType {
    case "ws":
        ws := map[string]interface{}{"path": getParam(params, "path", "/")}
        if host := getParam(params, "host", ""); host != "" {
            ws["host"] = host
        }
        ss["wsSettings"] = ws
    case "grpc":
        grpc := map[string]interface{}{}
        if sn := getParam(params, "serviceName", ""); sn != "" {
            grpc["serviceName"] = sn
        }
        if auth := getParam(params, "authority", ""); auth != "" {
            grpc["authority"] = auth
        }
        if mode := getParam(params, "mode", ""); mode == "multi" {
            grpc["multiMode"] = true
        }
        ss["grpcSettings"] = grpc
    case "xhttp", "splithttp":
        xhttp := map[string]interface{}{"path": getParam(params, "path", "/")}
        if host := getParam(params, "host", ""); host != "" {
            xhttp["host"] = host
        }
        if mode := getParam(params, "mode", ""); mode != "" {
            xhttp["mode"] = mode
        }
        ss["xhttpSettings"] = xhttp
    }

    if secType == "tls" {
        tls := map[string]interface{}{
            "serverName":    getParam(params, "sni", address),
            "allowInsecure": getBoolParam(params, "allowInsecure", false),
        }
        if getBoolParam(params, "insecure", false) {
            tls["allowInsecure"] = true
        }
        if alpn := getAlpnParam(params, "alpn"); alpn != nil {
            tls["alpn"] = alpn
        }
        if fp := getParam(params, "fp", ""); fp != "" {
            tls["fingerprint"] = fp
        }

        if encryption != "" {
            tls["encryption"] = encryption
        }
        ss["tlsSettings"] = tls
    } else if secType == "reality" {
        pbk := getParam(params, "pbk", "")
        if pbk == "" {
            return nil, fmt.Errorf("no pbk for reality")
        }
        reality := map[string]interface{}{
            "serverName":  getParam(params, "sni", ""),
            "fingerprint": getParam(params, "fp", "chrome"),
            "publicKey":   pbk,
            "shortId":     getParam(params, "sid", ""),
            "spiderX":     "",
        }

        if encryption != "" {
            reality["encryption"] = encryption
        }
        ss["realitySettings"] = reality
    }

    return outbound, nil
}


func parseHy2(uri string) (map[string]interface{}, error) {
    parsed, err := url.Parse(uri)
    if err != nil {
        return nil, err
    }
    password := parsed.User.String()
    if strings.Contains(password, ":") {
        password = strings.Split(password, ":")[0]
    }
    address := parsed.Hostname()
    portStr := parsed.Port()
    params := parsed.Query()

    var portInt uint16
    fmt.Sscanf(portStr, "%d", &portInt)

    serverConfig := map[string]interface{}{
        "address":  address,
        "port":     portInt,
        "password": password,
    }

    if sni := getParam(params, "sni", ""); sni != "" {
        serverConfig["sni"] = sni
    }
    if insecure := getBoolParam(params, "insecure", false); insecure {
        serverConfig["allowInsecure"] = true // В Xray используется allowInsecure
    }
    if obfs := getParam(params, "obfs", ""); obfs != "" {
        serverConfig["obfs"] = obfs
        serverConfig["obfsPassword"] = getParam(params, "obfs-password", "")
    }

    return map[string]interface{}{
        "protocol": "hysteria2",
        "settings": map[string]interface{}{
            "servers": []map[string]interface{}{serverConfig}, // По стандарту Xray
        },
    }, nil
}

func parseTuic(uri string) (map[string]interface{}, error) {
    parsed, err := url.Parse(uri)
    if err != nil {
        return nil, err
    }
    uuid := parsed.User.Username()
    password, _ := parsed.User.Password()
    address := parsed.Hostname()
    portStr := parsed.Port()
    params := parsed.Query()

    var portInt uint16
    fmt.Sscanf(portStr, "%d", &portInt)

    serverConfig := map[string]interface{}{
        "address":  address,
        "port":     portInt,
        "uuid":     uuid,
        "password": password,
    }

    if sni := getParam(params, "sni", ""); sni != "" {
        serverConfig["sni"] = sni
    }
    if alpn := getAlpnParam(params, "alpn"); alpn != nil {
        serverConfig["alpn"] = alpn
    }
    if cc := getParam(params, "congestion_control", ""); cc != "" {
        serverConfig["congestionControlType"] = cc
    }
    if uc := getParam(params, "udp_relay_mode", ""); uc != "" {
        serverConfig["udpRelayMode"] = uc
    }
    if insecure := getBoolParam(params, "allow_insecure", false); insecure {
        serverConfig["allowInsecure"] = true
    }

    return map[string]interface{}{
        "protocol": "tuic",
        "settings": map[string]interface{}{
            "servers": []map[string]interface{}{serverConfig}, // По стандарту Xray
        },
    }, nil
}
