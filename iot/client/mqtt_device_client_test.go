package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/huaweicloud/huaweicloud-iot-device-sdk-go/iot/config"
	"github.com/huaweicloud/huaweicloud-iot-device-sdk-go/iot/constants"
)

func TestConfigureTLSDisabledSkipsCertificates(t *testing.T) {
	for _, server := range []string{
		"mqtt://gateway.iot-mqtts.example.com:1883",
		"mqtts://example.com:8883",
		"ssl://example.com:8883",
	} {
		t.Run(server, func(t *testing.T) {
			for _, caPath := range []string{"", filepath.Join(t.TempDir(), "missing.pem")} {
				client := MqttDeviceClient{ConnectAuthConfig: &config.ConnectAuthConfig{
					Servers:         server,
					TlsEnable:       false,
					ServerCaPath:    caPath,
					AuthType:        constants.AuthTypeX509,
					CertFilePath:    "missing-cert.pem",
					CertKeyFilePath: "missing-key.pem",
				}}
				options := mqtt.NewClientOptions()
				if err := client.configureTLS(options); err != nil {
					t.Fatalf("关闭 TLS 时不应加载证书：%v", err)
				}
				if options.TLSConfig != nil {
					t.Fatal("关闭 TLS 时不应配置 TLSConfig")
				}
			}
		})
	}
}

func TestConfigureTLSEnabledLoadsCARegardlessOfServerURL(t *testing.T) {
	caPath := writeTestCA(t)
	for _, server := range []string{"mqtt://example.com:1883", "mqtts://example.com:8883", "abc://192.0.2.1:1883"} {
		t.Run(server, func(t *testing.T) {
			client := MqttDeviceClient{ConnectAuthConfig: &config.ConnectAuthConfig{
				Servers:      server,
				TlsEnable:    true,
				ServerCaPath: filepath.Join(t.TempDir(), "missing.pem"),
			}}
			options := mqtt.NewClientOptions()
			if err := client.configureTLS(options); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("开启 TLS 且 CA 缺失时应返回文件错误，实际：%v", err)
			}
			if options.TLSConfig != nil {
				t.Fatal("CA 加载失败时不应配置 TLSConfig")
			}
			client.ConnectAuthConfig.ServerCaPath = caPath
			if err := client.configureTLS(options); err != nil {
				t.Fatalf("开启 TLS 时加载有效 CA 失败：%v", err)
			}
			tlsConfig := options.TLSConfig
			if tlsConfig == nil || tlsConfig.RootCAs == nil || len(tlsConfig.RootCAs.Subjects()) != 1 {
				t.Fatal("开启 TLS 时应配置有效 CA")
			}
			if tlsConfig.MinVersion != tls.VersionTLS12 || tlsConfig.MaxVersion != tls.VersionTLS13 || tlsConfig.VerifyConnection == nil {
				t.Fatal("应保留现有 TLS 版本限制与证书校验")
			}
			client.ConnectAuthConfig.AuthType = constants.AuthTypeX509
			client.ConnectAuthConfig.CertFilePath = filepath.Join(t.TempDir(), "missing-cert.pem")
			client.ConnectAuthConfig.CertKeyFilePath = filepath.Join(t.TempDir(), "missing-key.pem")
			options = mqtt.NewClientOptions()
			if err := client.configureTLS(options); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("开启 TLS 和 X.509 认证时应加载设备证书，实际：%v", err)
			}
			if options.TLSConfig != nil {
				t.Fatal("设备证书加载失败时不应配置 TLSConfig")
			}
		})
	}
}

func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
