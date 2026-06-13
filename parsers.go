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
}

func getParam(params url.Values, key, fallback string) string {
    if val, ok := params[key]; ok && len(val) > 0 && val[0] != "" {
        return val[0]
    }
    return fallback
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

    outbound := map[string]interface{}{
        "protocol": "vless",
        "settings": map[string]interface{}{"vnext": []map[string]interface{}{{"address": address, "port": portInt, "users": []map[string]interface{}{{"id": uuid, "encryption": "none"}}}}},
        "streamSettings": map[string]interface{}{"network": getParam(params, "type", "tcp"), "security": getParam(params, "security", "none")},
    }

    netType := getParam(params, "type", "tcp")
    if netType == "ws" {
        ws := map[string]interface{}{"path": getParam(params, "path", "/")}
        if h := getParam(params, "host", ""); h != "" {
            ws["host"] = h
        }
        outbound["streamSettings"].(map[string]interface{})["wsSettings"] = ws
    }
    secType := getParam(params, "security", "none")
    if secType == "tls" {
        outbound["streamSettings"].(map[string]interface{})["tlsSettings"] = map[string]interface{}{"serverName": getParam(params, "sni", ""), "allowInsecure": false}
    } else if secType == "reality" {
        pbk := getParam(params, "pbk", "")
        if pbk == "" {
            return nil, fmt.Errorf("no pbk")
        }
        outbound["streamSettings"].(map[string]interface{})["realitySettings"] = map[string]interface{}{"serverName": getParam(params, "sni", ""), "fingerprint": getParam(params, "fp", "chrome"), "publicKey": pbk, "shortId": getParam(params, "sid", ""), "spiderX": ""}
    }
    return outbound, nil
}

func parseVMess(uri string) (map[string]interface{}, error) {
    if !strings.HasPrefix(uri, "vmess://") {
        return nil, fmt.Errorf("not vmess")
    }
    b64 := strings.TrimPrefix(uri, "vmess://")
    if len(b64)%4 != 0 {
        b64 += strings.Repeat("=", 4-len(b64)%4)
    }
    decoded, err := base64.StdEncoding.DecodeString(b64)
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
        "settings": map[string]interface{}{"vnext": []map[string]interface{}{{"address": v.Add, "port": portInt, "users": []map[string]interface{}{{"id": v.Id, "alterId": aid, "security": v.Scy}}}}},
        "streamSettings": map[string]interface{}{"network": v.Net, "security": v.Tls},
    }
    if v.Net == "ws" {
        ws := map[string]interface{}{"path": v.Path}
        if v.Host != "" {
            ws["host"] = v.Host
        }
        outbound["streamSettings"].(map[string]interface{})["wsSettings"] = ws
    }
    if v.Tls == "tls" {
        outbound["streamSettings"].(map[string]interface{})["tlsSettings"] = map[string]interface{}{"serverName": v.Sni, "allowInsecure": false}
    }
    return outbound, nil
}

func parseShadowsocks(uri string) (map[string]interface{}, error) {
    if !strings.HasPrefix(uri, "ss://") {
        return nil, fmt.Errorf("not ss")
    }
    b64WithRest := strings.TrimPrefix(uri, "ss://")
    parts := strings.SplitN(b64WithRest, "@", 2)
    if len(parts) != 2 {
        return nil, fmt.Errorf("invalid ss format")
    }
    if len(parts[0])%4 != 0 {
        parts[0] += strings.Repeat("=", 4-len(parts[0])%4)
    }
    decoded, err := base64.StdEncoding.DecodeString(parts[0])
    if err != nil {
        return nil, err
    }
    methodPass := strings.SplitN(string(decoded), ":", 2)
    if len(methodPass) != 2 {
        return nil, fmt.Errorf("invalid ss credentials")
    }
    hostPort := strings.SplitN(parts[1], "#", 2)[0]
    host, portStr, err := net.SplitHostPort(hostPort)
    if err != nil {
        return nil, err
    }
    var portInt uint16
    fmt.Sscanf(portStr, "%d", &portInt)
    return map[string]interface{}{
        "protocol": "shadowsocks",
        "settings": map[string]interface{}{"servers": []map[string]interface{}{{"address": host, "port": portInt, "method": methodPass[0], "password": methodPass[1]}}},
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
    return map[string]interface{}{
        "protocol": "trojan",
        "settings": map[string]interface{}{"servers": []map[string]interface{}{{"address": address, "port": portInt, "password": password}}},
        "streamSettings": map[string]interface{}{"network": getParam(params, "type", "tcp"), "security": "tls", "tlsSettings": map[string]interface{}{"serverName": getParam(params, "sni", address), "allowInsecure": false}},
    }, nil
}
