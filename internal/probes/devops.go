package probes

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/demicloud/net-scope/internal/scan"
)

func registerDevOps() {
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "docker-api", Group: "DevOps / APIs", Name: "Docker [Version]",
		ServiceName: "Docker API",
		DefaultPort: 2375, Transport: "TCP", Run: probeDockerAPI,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "prometheus", Group: "DevOps / APIs", Name: "Prometheus [Metrics]",
		ServiceName: "Prometheus Server",
		DefaultPort: 9090, Transport: "TCP", Run: probePrometheus,
	})
	scan.RegisterDeepProbe(scan.DeepProbe{
		ID: "vault", Group: "DevOps / APIs", Name: "Vault [Health]",
		ServiceName: "Vault Server",
		DefaultPort: 8200, Transport: "TCP", Run: probeVault,
	})
}

func probeDockerAPI(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Docker API)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending GET /version…")
	statusLine, body, err := httpGetBody(conn, joinHost(ip, port), "/version")
	if err != nil {
		emit("Request failed: " + err.Error())
		return nil, nil
	}
	emit("Status: " + statusLine)

	var result []scan.Observation
	if !strings.Contains(statusLine, "200") {
		emit("Non-200 response — Docker API may require TLS or authentication")
		return result, nil
	}
	emit("⚠  CRITICAL: Docker API is accessible without authentication!")
	result = append(result, obs("probe", "docker_auth", "none"))

	for _, line := range strings.Split(strings.ReplaceAll(body, ",", "\n"), "\n") {
		if v := jsonStr(line, "Version"); v != "" {
			emit("Docker version:   " + v)
			result = append(result, obs("probe", "version", v))
		}
		if v := jsonStr(line, "ApiVersion"); v != "" {
			emit("API version:      " + v)
			result = append(result, obs("probe", "docker_api_version", v))
		}
		if v := jsonStr(line, "Os"); v != "" {
			emit("OS:               " + v)
		}
		if v := jsonStr(line, "Arch"); v != "" {
			emit("Arch:             " + v)
		}
		if v := jsonStr(line, "KernelVersion"); v != "" {
			emit("Kernel:           " + v)
		}
	}
	return result, nil
}

func probePrometheus(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Prometheus)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending GET /api/v1/status/buildinfo…")
	statusLine, body, err := httpGetBody(conn, joinHost(ip, port), "/api/v1/status/buildinfo")
	if err != nil {
		emit("Request failed: " + err.Error())
		return nil, nil
	}
	emit("Status: " + statusLine)
	if !strings.Contains(statusLine, "200") {
		emit("Non-200 response — may not be Prometheus or authentication is required")
		return nil, nil
	}
	emit("⚠  Prometheus metrics endpoint is accessible without authentication!")

	var result []scan.Observation
	result = append(result, obs("probe", "prometheus_auth", "none"))

	for _, line := range strings.Split(strings.ReplaceAll(body, ",", "\n"), "\n") {
		if v := jsonStr(line, "version"); v != "" {
			emit("Version:   " + v)
			result = append(result, obs("probe", "version", v))
		}
		if v := jsonStr(line, "goVersion"); v != "" {
			emit("Go:        " + v)
		}
	}
	return result, nil
}

func probeVault(_ context.Context, ip string, port int, dial scan.DialFunc, emit func(string)) ([]scan.Observation, error) {
	emit(fmt.Sprintf("Connecting to %s (Vault)…", joinHost(ip, port)))
	conn, err := dialTCP(context.Background(), dial, ip, port, 5*time.Second)
	if err != nil {
		emit("Connection failed: " + err.Error())
		return nil, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	emit("Sending GET /v1/sys/health…")
	statusLine, _, err := httpGetBody(conn, joinHost(ip, port), "/v1/sys/health")
	if err != nil {
		emit("Request failed: " + err.Error())
		return nil, nil
	}
	emit("Status: " + statusLine)

	var result []scan.Observation
	switch {
	case strings.Contains(statusLine, "200"):
		emit("Vault is initialized and unsealed")
		result = append(result, obs("probe", "vault_status", "initialized_unsealed"))
	case strings.Contains(statusLine, "429"):
		emit("Vault is unsealed and standby (429 Standby)")
		result = append(result, obs("probe", "vault_status", "standby"))
	case strings.Contains(statusLine, "472"):
		emit("Vault is unsealed and in DR secondary mode")
		result = append(result, obs("probe", "vault_status", "dr_secondary"))
	case strings.Contains(statusLine, "473"):
		emit("Vault is unsealed and in performance standby mode")
		result = append(result, obs("probe", "vault_status", "perf_standby"))
	case strings.Contains(statusLine, "501"):
		emit("⚠  Vault is not initialized!")
		result = append(result, obs("probe", "vault_status", "not_initialized"))
	case strings.Contains(statusLine, "503"):
		emit("⚠  Vault is sealed — data is inaccessible")
		result = append(result, obs("probe", "vault_status", "sealed"))
	default:
		emit("Unknown Vault state: " + statusLine)
	}
	return result, nil
}
