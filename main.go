package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// ----------------------- XML 数据结构定义 -----------------------

// AndroidAttestation 表示整个 XML 文档
type AndroidAttestation struct {
	XMLName          xml.Name `xml:"AndroidAttestation"`
	NumberOfKeyboxes int      `xml:"NumberOfKeyboxes"`
	Keyboxes         []Keybox `xml:"Keybox"`
}

// Keybox 表示设备的 Keybox，包含一个或多个 Key
type Keybox struct {
	DeviceID string `xml:"DeviceID,attr"`
	Keys     []Key  `xml:"Key"`
}

// Key 表示单个密钥对及其证书链
type Key struct {
	Algorithm        string            `xml:"algorithm,attr"`
	PrivateKey       PEMBlock          `xml:"PrivateKey"`
	CertificateChain *CertificateChain `xml:"CertificateChain,omitempty"`
}

// PEMBlock 封装 PEM 数据及格式说明
type PEMBlock struct {
	Format string `xml:"format,attr"`
	Value  string `xml:",chardata"`
}

// CertificateChain 表示证书链结构
type CertificateChain struct {
	NumberOfCertificates int        `xml:"NumberOfCertificates"`
	Certificates         []PEMBlock `xml:"Certificate"`
}

// ----------------------- XML 解析与反解析 -----------------------

// LoadAttestationFromFile 通过 keybox.xml 文件加载 Attestation 数据
func LoadAttestationFromFile(filename string) (*AndroidAttestation, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var att AndroidAttestation
	err = xml.Unmarshal(data, &att)
	if err != nil {
		return nil, err
	}
	att.NumberOfKeyboxes = len(att.Keyboxes)
	return &att, nil
}

// SaveToFile 将 Attestation 数据反解析为 XML 文件保存
func (a *AndroidAttestation) SaveToFile(filename string) error {
	a.NumberOfKeyboxes = len(a.Keyboxes)
	data, err := xml.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	data = append([]byte(xml.Header), data...)
	return os.WriteFile(filename, data, 0644)
}

// ----------------------- 辅助函数 -----------------------

// cleanupPEM 去除 PEM 数据中的多余空白（对每行 trim）
func cleanupPEM(pemStr string) string {
	lines := strings.Split(pemStr, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}

// ----------------------- PEM 与证书/密钥处理 -----------------------

// ParsePrivateKey 解析 PEM 格式的私钥（支持 ECDSA、RSA、PKCS8）
func ParsePrivateKey(pemStr string) (interface{}, error) {
	pemStr = cleanupPEM(pemStr)
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("解析 PEM 数据失败")
	}
	if strings.Contains(block.Type, "EC") {
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
	}
	if strings.Contains(block.Type, "RSA") {
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("不支持的私钥格式")
}

// PrivateKeyToPEM 将私钥转换为 PEM 格式字符串
func PrivateKeyToPEM(key interface{}) (string, error) {
	var block *pem.Block
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", err
		}
		block = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		}
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: b,
		}
	default:
		return "", errors.New("不支持的私钥类型")
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ParseCertificate 解析 PEM 格式的证书
func ParseCertificate(pemStr string) (*x509.Certificate, error) {
	pemStr = cleanupPEM(pemStr)
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("解析证书 PEM 数据失败")
	}
	return x509.ParseCertificate(block.Bytes)
}

// CertificateToPEM 将证书转换为 PEM 格式字符串
func CertificateToPEM(cert *x509.Certificate) (string, error) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ----------------------- 证书生成函数 -----------------------

// GenerateSubordinateCertificate 生成下一级证书及密钥（以 ECDSA 为例）
// parentCert 与 parentKey 为签发者信息，subject 为证书主题
func GenerateSubordinateCertificate(parentCert *x509.Certificate, parentKey interface{}, subject string) (certPEM string, keyPEM string, err error) {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 有效期 1 年
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, &newKey.PublicKey, parentKey)
	if err != nil {
		return "", "", err
	}
	certBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyBytes, err := x509.MarshalECPrivateKey(newKey)
	if err != nil {
		return "", "", err
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	return string(certBlock), string(keyBlock), nil
}

// GenerateSelfSignedCACertificate 从头生成自签 CA 证书及私钥（以 ECDSA 为例）
func GenerateSelfSignedCACertificate(subject string) (certPEM string, keyPEM string, caCert *x509.Certificate, caKey interface{}, err error) {
	caKeyECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", "", nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0), // 有效期 5 年
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &caKeyECDSA.PublicKey, caKeyECDSA)
	if err != nil {
		return "", "", nil, nil, err
	}
	certBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyBytes, err := x509.MarshalECPrivateKey(caKeyECDSA)
	if err != nil {
		return "", "", nil, nil, err
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	caCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return "", "", nil, nil, err
	}
	return string(certBlock), string(keyBlock), caCert, caKeyECDSA, nil
}

// ----------------------- 菜单操作与主流程 -----------------------

var (
	// 全局变量：当前 Attestation 数据、CA 证书及私钥
	attestation *AndroidAttestation
	caCert      *x509.Certificate
	caKey       interface{}
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("====== Android Attestation Keybox Generator ======")
		fmt.Println("1. 从 keybox.xml 导入（现有证书链+密钥）")
		fmt.Println("2. 导入已有 CA 证书及私钥")
		fmt.Println("3. 从头开始生成（现场生成 CA）")
		fmt.Println("4. 生成下一级证书+密钥 (可重复执行)")
		fmt.Println("5. 查看当前 Attestation 信息")
		fmt.Println("6. 保存到 keybox.xml 并退出")
		fmt.Print("请输入选项：")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			fmt.Print("请输入 keybox.xml 文件路径：")
			file, _ := reader.ReadString('\n')
			file = strings.TrimSpace(file)
			a, err := LoadAttestationFromFile(file)
			if err != nil {
				fmt.Println("加载 XML 失败：", err)
			} else {
				attestation = a
				fmt.Println("成功加载 keybox.xml！")
			}
		case "2":
			fmt.Print("请输入 CA 证书文件路径（PEM 格式）：")
			certFile, _ := reader.ReadString('\n')
			certFile = strings.TrimSpace(certFile)
			fmt.Print("请输入 CA 私钥文件路径（PEM 格式）：")
			keyFile, _ := reader.ReadString('\n')
			keyFile = strings.TrimSpace(keyFile)
			caCertData, err := os.ReadFile(certFile)
			if err != nil {
				fmt.Println("读取 CA 证书文件错误：", err)
				break
			}
			caCertParsed, err := ParseCertificate(string(caCertData))
			if err != nil {
				fmt.Println("解析 CA 证书失败：", err)
				break
			}
			caKeyData, err := os.ReadFile(keyFile)
			if err != nil {
				fmt.Println("读取 CA 私钥文件错误：", err)
				break
			}
			caKeyParsed, err := ParsePrivateKey(string(caKeyData))
			if err != nil {
				fmt.Println("解析 CA 私钥失败：", err)
				break
			}
			caCert = caCertParsed
			caKey = caKeyParsed
			fmt.Println("成功导入 CA 证书及私钥")
			fmt.Print("请输入主题（CommonName）：")
			keyPEM, err := PrivateKeyToPEM(caKey)
			if err != nil {
				fmt.Println("转换 CA 密钥为 PEM 失败：", err)
				break
			}
			certPEM, err := CertificateToPEM(caCert)
			if err != nil {
				fmt.Println("转换 CA 证书/密钥为 PEM 失败：", err)
				break
			}
			subject, _ := reader.ReadString('\n')
			subject = strings.TrimSpace(subject)
			attestation = &AndroidAttestation{
				Keyboxes: []Keybox{
					{
						DeviceID: subject,
						Keys: []Key{
							{
								Algorithm: "ecdsa",
								PrivateKey: PEMBlock{
									Format: "pem",
									Value:  keyPEM,
								},
								CertificateChain: &CertificateChain{
									NumberOfCertificates: 1,
									Certificates: []PEMBlock{
										{
											Format: "pem",
											Value:  certPEM,
										},
									},
								},
							},
						},
					},
				},
			}
			fmt.Println("构造新的 Attestation 成功")
		case "3":
			fmt.Print("请输入 CA 证书主题（CommonName）：")
			subject, _ := reader.ReadString('\n')
			subject = strings.TrimSpace(subject)
			certPEM, keyPEM, newCACert, newCAKey, err := GenerateSelfSignedCACertificate(subject)
			if err != nil {
				fmt.Println("生成 CA 失败：", err)
				break
			}
			caCert = newCACert
			caKey = newCAKey
			fmt.Println("成功生成 CA 证书及私钥")
			// 构造新的 Attestation，默认创建一个 Keybox，其中 CA 同时作为设备密钥使用
			attestation = &AndroidAttestation{
				Keyboxes: []Keybox{
					{
						DeviceID: subject,
						Keys: []Key{
							{
								Algorithm: "ecdsa",
								PrivateKey: PEMBlock{
									Format: "pem",
									Value:  keyPEM,
								},
								CertificateChain: &CertificateChain{
									NumberOfCertificates: 1,
									Certificates: []PEMBlock{
										{
											Format: "pem",
											Value:  certPEM,
										},
									},
								},
							},
						},
					},
				},
			}
			fmt.Println("构造新的 Attestation 成功")
		case "4":
			if attestation == nil {
				fmt.Println("请先加载/生成 Attestation 数据！")
				break
			}
			// 遍历每个 Keybox、每个 Key，生成下一级证书+密钥
			for i, kb := range attestation.Keyboxes {
				for j, key := range kb.Keys {
					if key.CertificateChain != nil && len(key.CertificateChain.Certificates) > 0 {
						// 取当前 Key 的证书链中第一个证书作为父证书
						parentCertPEM := key.CertificateChain.Certificates[0].Value
						parentCert, err := ParseCertificate(parentCertPEM)
						if err != nil {
							fmt.Printf("Keybox %d Key %d: 解析父证书失败: %v\n", i, j, err)
							continue
						}
						parentKey, err := ParsePrivateKey(key.PrivateKey.Value)
						if err != nil {
							fmt.Printf("Keybox %d Key %d: 解析私钥失败: %v\n", i, j, err)
							continue
						}
						signerCert := parentCert
						signerKey := parentKey
						newCertPEM, newKeyPEM, err := GenerateSubordinateCertificate(signerCert, signerKey, kb.DeviceID)
						if err != nil {
							fmt.Printf("Keybox %d Key %d: 生成下一级证书失败: %v\n", i, j, err)
							continue
						}
						// 将新生成的证书追加到证书链中，并更新私钥
						key.CertificateChain.Certificates = append([]PEMBlock{{
							Format: "pem",
							Value:  newCertPEM,
						}}, key.CertificateChain.Certificates...)
						key.CertificateChain.NumberOfCertificates = len(key.CertificateChain.Certificates)
						key.PrivateKey.Value = newKeyPEM
						attestation.Keyboxes[i].Keys[j] = key
						fmt.Printf("Keybox %d Key %d: 成功生成下一级证书\n", i, j)
					} else {
						fmt.Printf("Keybox %d Key %d: 无证书链，无法生成下一级证书\n", i, j)
					}
				}
			}
		case "5":
			if attestation == nil {
				fmt.Println("当前无 Attestation 数据")
			} else {
				data, _ := xml.MarshalIndent(attestation, "", "  ")
				fmt.Println("当前 Attestation 信息：")
				fmt.Println(string(data))
			}
		case "6":
			fmt.Print("请输入保存的 keybox.xml 文件路径：")
			outfile, _ := reader.ReadString('\n')
			outfile = strings.TrimSpace(outfile)
			if attestation == nil {
				fmt.Println("无 Attestation 数据可保存")
				os.Exit(1)
			}
			err := attestation.SaveToFile(outfile)
			if err != nil {
				fmt.Println("保存 XML 失败：", err)
			} else {
				fmt.Println("成功保存到", outfile)
			}
			os.Exit(0)
		default:
			fmt.Println("无效选项，请重新输入")
		}
	}
}
