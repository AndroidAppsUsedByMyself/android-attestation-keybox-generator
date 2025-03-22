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
	"flag"
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

// ----------------------- XML 解析与反解析方法 -----------------------

func (a *AndroidAttestation) SaveToFile(filename string) error {
	a.NumberOfKeyboxes = len(a.Keyboxes)
	data, err := xml.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	data = append([]byte(xml.Header), data...)
	return os.WriteFile(filename, data, 0644)
}

func LoadAttestationFromFile(filename string) (*AndroidAttestation, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var att AndroidAttestation
	if err = xml.Unmarshal(data, &att); err != nil {
		return nil, err
	}
	att.NumberOfKeyboxes = len(att.Keyboxes)
	return &att, nil
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

func readLine(prompt string, reader *bufio.Reader) (string, error) {
	fmt.Print(prompt)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

// ----------------------- PEM 与证书/密钥处理函数 -----------------------

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
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
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
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return string(pem.EncodeToMemory(block)), nil
}

// ----------------------- 证书生成函数 -----------------------
// parentCert 与 parentKey 为签发者信息，subject 为证书主题

// GenerateSubordinateCertificateECDSA 生成下一级证书及密钥，ECDSA版本
func GenerateSubordinateCertificateECDSA(parentCert *x509.Certificate, parentKey interface{}, subject string) (string, string, error) {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, &newKey.PublicKey, parentKey)
	if err != nil {
		return "", "", err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	keyBytes, err := x509.MarshalECPrivateKey(newKey)
	if err != nil {
		return "", "", err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	return certPEM, keyPEM, nil
}

func GenerateSubordinateCertificateRSA(parentCert *x509.Certificate, parentKey interface{}, subject string) (string, string, error) {
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, &newKey.PublicKey, parentKey)
	if err != nil {
		return "", "", err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	keyBytes := x509.MarshalPKCS1PrivateKey(newKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))
	return certPEM, keyPEM, nil
}

// GenerateSelfSignedCACertificateECDSA 从头生成自签 CA 证书及私钥，ECDSA版本
func GenerateSelfSignedCACertificateECDSA(subject string) (string, string, *x509.Certificate, interface{}, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", "", nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", nil, nil, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	keyBytes, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return "", "", nil, nil, err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return "", "", nil, nil, err
	}
	return certPEM, keyPEM, caCert, caKey, nil
}

func GenerateSelfSignedCACertificateRSA(subject string) (string, string, *x509.Certificate, interface{}, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", "", nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", nil, nil, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	keyBytes := x509.MarshalPKCS1PrivateKey(caKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))
	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return "", "", nil, nil, err
	}
	return certPEM, keyPEM, caCert, caKey, nil
}

// ----------------------- 证书链与密钥对验证 -----------------------

func VerifyCertificateChain(certPEMs []string) error {
	certs := make([]*x509.Certificate, len(certPEMs))
	for i, pemStr := range certPEMs {
		cert, err := ParseCertificate(pemStr)
		if err != nil {
			return fmt.Errorf("解析证书 %d 失败: %v", i, err)
		}
		certs[i] = cert
	}
	brokenLinks := 0
	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		issuerCert := certs[i+1]

		fmt.Printf("验证证书 %d:\n", i)
		fmt.Printf("  主题 (Subject): %s\n", cert.Subject.CommonName)
		fmt.Printf("  颁发者 (Issuer): %s\n", cert.Issuer.CommonName)
		fmt.Printf("验证证书 %d:\n", i+1)
		fmt.Printf("  主题 (Subject): %s\n", issuerCert.Subject.CommonName)
		fmt.Printf("  颁发者 (Issuer): %s\n", issuerCert.Issuer.CommonName)

		if cert.Issuer.CommonName != issuerCert.Subject.CommonName {
			fmt.Printf("[破坏] 证书 %d 颁发者与证书 %d 主题不匹配\n", i, i+1)
			brokenLinks++
			continue
		}

		err := cert.CheckSignatureFrom(issuerCert)
		if err != nil {
			fmt.Printf("[破坏] 证书 %d 无法由证书 %d 验证: %v\n", i, i+1, err)
			brokenLinks++
		} else {
			fmt.Printf("[成功] 证书 %d 由证书 %d 成功验证\n", i, i+1)
		}
	}
	if brokenLinks > 0 {
		return fmt.Errorf("证书链中发现 %d 处破坏", brokenLinks)
	}
	fmt.Println("证书链验证成功")
	return nil
}

// VerifyKeyCertificatePair 验证证书和私钥是否匹配
func VerifyKeyCertificatePair(certPEM, privateKeyPEM string) error {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("解析证书失败: %v", err)
	}
	privateKey, err := ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("解析私钥失败: %v", err)
	}
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if !key.PublicKey.Equal(cert.PublicKey) {
			return errors.New("证书的公钥与提供的私钥不匹配")
		}
	case *rsa.PrivateKey:
		if !key.PublicKey.Equal(cert.PublicKey) {
			return errors.New("证书的公钥与提供的私钥不匹配")
		}
	default:
		return errors.New("不支持的私钥类型")
	}
	fmt.Println("[成功] 证书和密钥匹配")
	return nil
}

// ----------------------- 应用封装 -----------------------

type App struct {
	attestation *AndroidAttestation
	caCert      *x509.Certificate
	caKey       interface{}
	reader      *bufio.Reader
}

func NewApp() *App {
	return &App{
		reader: bufio.NewReader(os.Stdin),
	}
}

func (app *App) RunInteractive() {
	for {
		app.showMenu()
		choice, err := readLine("请输入选项：", app.reader)
		if err != nil {
			fmt.Println("读取输入错误：", err)
			continue
		}
		switch choice {
		case "1":
			app.importAttestation()
		case "2":
			app.importCA()
		case "3":
			app.generateCA()
		case "4":
			app.generateSubCert()
		case "5":
			app.showAttestation()
		case "6":
			app.saveAndExit()
		case "7":
			app.verifyAll()
		default:
			fmt.Println("无效选项，请重新输入")
		}
	}
}

func (app *App) showMenu() {
	fmt.Println("====== Android Attestation Keybox Generator ======")
	fmt.Println("1. 从 keybox.xml 导入（现有证书链+密钥）")
	fmt.Println("2. 导入已有 CA 证书及私钥")
	fmt.Println("3. 从头开始生成 CA")
	fmt.Println("4. 生成下一级证书+密钥 (可重复执行)")
	fmt.Println("5. 查看当前 Attestation 信息")
	fmt.Println("6. 保存到 keybox.xml 并退出")
	fmt.Println("7. 验证证书链和密钥对")
}

func (app *App) importAttestation() {
	file, err := readLine("请输入 keybox.xml 文件路径：", app.reader)
	if err != nil {
		fmt.Println("读取文件路径错误：", err)
		return
	}
	a, err := LoadAttestationFromFile(file)
	if err != nil {
		fmt.Println("加载 XML 失败：", err)
	} else {
		app.attestation = a
		fmt.Println("成功加载 keybox.xml！")
	}
}

func (app *App) importCA() {
	certFile, err := readLine("请输入 CA 证书文件路径（PEM 格式）：", app.reader)
	if err != nil {
		fmt.Println("读取错误：", err)
		return
	}
	keyFile, err := readLine("请输入 CA 私钥文件路径（PEM 格式）：", app.reader)
	if err != nil {
		fmt.Println("读取错误：", err)
		return
	}
	caCertData, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Println("读取 CA 证书文件错误：", err)
		return
	}
	caCertParsed, err := ParseCertificate(string(caCertData))
	if err != nil {
		fmt.Println("解析 CA 证书失败：", err)
		return
	}
	caKeyData, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Println("读取 CA 私钥文件错误：", err)
		return
	}
	caKeyParsed, err := ParsePrivateKey(string(caKeyData))
	if err != nil {
		fmt.Println("解析 CA 私钥失败：", err)
		return
	}
	app.caCert = caCertParsed
	app.caKey = caKeyParsed
	// 构造新的 Attestation 数据
	keyPEM, _ := PrivateKeyToPEM(app.caKey)
	certPEM, _ := CertificateToPEM(app.caCert)
	app.attestation = &AndroidAttestation{
		Keyboxes: []Keybox{
			{
				DeviceID: "",
				Keys: []Key{
					{
						Algorithm:  "ecdsa",
						PrivateKey: PEMBlock{Format: "pem", Value: keyPEM},
						CertificateChain: &CertificateChain{
							NumberOfCertificates: 1,
							Certificates: []PEMBlock{
								{Format: "pem", Value: certPEM},
							},
						},
					},
				},
			},
		},
	}
	fmt.Println("成功导入 CA 证书及私钥，并构造新的 Attestation 数据")
}

func (app *App) generateCA() {
	subject, err := readLine("请输入 Subject: ", app.reader)
	if err != nil {
		fmt.Println("读取错误：", err)
		return
	}
	caType, err := readLine("请选择根 CA 类型 (ecdsa/rsa): ", app.reader)
	if err != nil {
		fmt.Println("读取错误：", err)
		return
	}
	caType = strings.ToLower(caType)
	var (
		certPEM, keyPEM string
		newCACert       *x509.Certificate
		newCAKey        interface{}
	)
	switch caType {
	case "rsa":
		certPEM, keyPEM, newCACert, newCAKey, err = GenerateSelfSignedCACertificateRSA(subject)
	default:
		certPEM, keyPEM, newCACert, newCAKey, err = GenerateSelfSignedCACertificateECDSA(subject)
		caType = "ecdsa"
	}
	if err != nil {
		fmt.Printf("生成 %s CA 失败: %v\n", strings.ToUpper(caType), err)
		return
	}
	app.caCert = newCACert
	app.caKey = newCAKey
	fmt.Printf("成功生成 %s CA 证书及私钥\n", strings.ToUpper(caType))
	// 如果尚未构造 attestation，则构造之
	if app.attestation == nil {
		app.attestation = &AndroidAttestation{
			Keyboxes: []Keybox{
				{
					DeviceID: "",
					Keys: []Key{
						{
							Algorithm:  caType,
							PrivateKey: PEMBlock{Format: "pem", Value: keyPEM},
							CertificateChain: &CertificateChain{
								NumberOfCertificates: 1,
								Certificates: []PEMBlock{
									{Format: "pem", Value: certPEM},
								},
							},
						},
					},
				},
			},
		}
	}
}

func (app *App) generateSubCert() {
	if app.attestation == nil {
		fmt.Println("请先加载/生成 Attestation 数据！")
		return
	}
	for kbIndex, kb := range app.attestation.Keyboxes {
		for keyIndex, key := range kb.Keys {
			if key.CertificateChain == nil || len(key.CertificateChain.Certificates) == 0 {
				fmt.Printf("Keybox %d Key %d: 无证书链，无法生成下一级证书\n", kbIndex, keyIndex)
				continue
			}
			parentCertPEM := key.CertificateChain.Certificates[0].Value
			parentCert, err := ParseCertificate(parentCertPEM)
			if err != nil {
				fmt.Printf("Keybox %d Key %d: 解析父证书失败: %v\n", kbIndex, keyIndex, err)
				continue
			}
			parentKey, err := ParsePrivateKey(key.PrivateKey.Value)
			if err != nil {
				fmt.Printf("Keybox %d Key %d: 解析私钥失败: %v\n", kbIndex, keyIndex, err)
				continue
			}
			fmt.Printf("当前 Key 的算法为: %s\n", key.Algorithm)
			subject, err := readLine("请输入 Subject: ", app.reader)
			if err != nil {
				fmt.Println("读取错误：", err)
				continue
			}
			subAlg, err := readLine("请选择下一级证书算法 (ecdsa/rsa): ", app.reader)
			if err != nil {
				fmt.Println("读取错误：", err)
				continue
			}
			subAlg = strings.ToLower(subAlg)
			var newCertPEM, newKeyPEM string
			if subAlg == "rsa" {
				newCertPEM, newKeyPEM, err = GenerateSubordinateCertificateRSA(parentCert, parentKey, subject)
			} else {
				newCertPEM, newKeyPEM, err = GenerateSubordinateCertificateECDSA(parentCert, parentKey, subject)
				subAlg = "ecdsa"
			}
			if err != nil {
				fmt.Printf("Keybox %d Key %d: 生成下一级证书失败: %v\n", kbIndex, keyIndex, err)
				continue
			}
			// 将新生成的证书链追加到前面
			key.CertificateChain.Certificates = append([]PEMBlock{{Format: "pem", Value: newCertPEM}}, key.CertificateChain.Certificates...)
			key.CertificateChain.NumberOfCertificates = len(key.CertificateChain.Certificates)
			key.PrivateKey.Value = newKeyPEM
			key.Algorithm = subAlg
			app.attestation.Keyboxes[kbIndex].Keys[keyIndex] = key
			fmt.Printf("Keybox %d Key %d: 成功生成下一级证书\n", kbIndex, keyIndex)
		}
	}
}

func (app *App) showAttestation() {
	if app.attestation == nil {
		fmt.Println("当前无 Attestation 数据")
		return
	}
	data, _ := xml.MarshalIndent(app.attestation, "", "  ")
	fmt.Println("当前 Attestation 信息：")
	fmt.Println(string(data))
}

func (app *App) saveAndExit() {
	outfile, err := readLine("请输入保存的 keybox.xml 文件路径：", app.reader)
	if err != nil {
		fmt.Println("读取文件路径错误：", err)
		return
	}
	if app.attestation == nil {
		fmt.Println("无 Attestation 数据可保存")
		os.Exit(1)
	}
	// 若存在空的 DeviceID 则提示填写
	for i, kb := range app.attestation.Keyboxes {
		if kb.DeviceID == "" {
			deviceID, _ := readLine(fmt.Sprintf("Keybox %d: DeviceID 为空，请输入 DeviceID:\n", i), app.reader)
			app.attestation.Keyboxes[i].DeviceID = deviceID
		}
	}
	if err := app.attestation.SaveToFile(outfile); err != nil {
		fmt.Println("保存 XML 失败：", err)
	} else {
		fmt.Println("成功保存到", outfile)
	}
	os.Exit(0)
}

func (app *App) verifyAll() {
	if app.attestation == nil {
		fmt.Println("请先加载/生成 Attestation 数据！")
		return
	}
	for _, kb := range app.attestation.Keyboxes {
		for _, key := range kb.Keys {
			if key.CertificateChain != nil && len(key.CertificateChain.Certificates) > 0 {
				certPEMs := make([]string, len(key.CertificateChain.Certificates))
				for i, cert := range key.CertificateChain.Certificates {
					certPEMs[i] = cert.Value
				}
				if err := VerifyCertificateChain(certPEMs); err != nil {
					fmt.Printf("验证证书链失败: %v\n", err)
				}
				if key.PrivateKey.Value != "" {
					if err := VerifyKeyCertificatePair(certPEMs[0], key.PrivateKey.Value); err != nil {
						fmt.Printf("验证密钥对失败: %v\n", err)
					}
				}
			}
		}
	}
}

// ----------------------- 命令行参数处理 -----------------------

func printUsage() {
	usage := `用法:
  若不带参数则进入交互模式，交互式输入指令；
  也可使用以下纯指令参数：
    -importAttestation 文件路径      从指定 XML 文件导入 Attestation 数据
    -importCA certFile keyFile        导入 CA 证书及私钥（PEM 格式）
    -generateCA subject caType        根据 subject 生成自签 CA (caType: ecdsa 或 rsa)
    -generateSubCert                生成下一级证书（需先导入或生成 Attestation）
    -showAttestation                显示当前 Attestation 信息
    -save outfile                   保存 Attestation 数据到 outfile 并退出
    -verify                       验证证书链和密钥对
`
	fmt.Println(usage)
}

func main() {
	// 定义命令行参数，若参数存在则执行相应操作，否则进入交互模式
	importAttestationPath := flag.String("importAttestation", "", "从指定 XML 文件导入 Attestation 数据")
	importCACert := flag.String("importCACert", "", "导入 CA 证书文件路径（PEM 格式）")
	importCAKey := flag.String("importCAKey", "", "导入 CA 私钥文件路径（PEM 格式）")
	generateCASubject := flag.String("generateCA", "", "根据 subject 生成自签 CA，参数格式：subject:caType (caType 可选 ecdsa/rsa，默认为 ecdsa)")
	generateSubCert := flag.Bool("generateSubCert", false, "生成下一级证书")
	showAttestation := flag.Bool("showAttestation", false, "显示当前 Attestation 信息")
	saveFile := flag.String("save", "", "保存 Attestation 数据到 outfile 并退出")
	verifyFlag := flag.Bool("verify", false, "验证证书链和密钥对")
	helpFlag := flag.Bool("help", false, "显示帮助")
	flag.Parse()

	app := NewApp()

	if *helpFlag {
		printUsage()
		return
	}

	// 若存在命令行参数，则按参数执行（非交互模式）
	switch {
	case *importAttestationPath != "":
		a, err := LoadAttestationFromFile(*importAttestationPath)
		if err != nil {
			fmt.Println("加载 XML 失败：", err)
			return
		}
		app.attestation = a
		fmt.Println("成功加载 Attestation 数据")
	case *importCACert != "" && *importCAKey != "":
		caCertData, err := os.ReadFile(*importCACert)
		if err != nil {
			fmt.Println("读取 CA 证书文件错误：", err)
			return
		}
		caCertParsed, err := ParseCertificate(string(caCertData))
		if err != nil {
			fmt.Println("解析 CA 证书失败：", err)
			return
		}
		caKeyData, err := os.ReadFile(*importCAKey)
		if err != nil {
			fmt.Println("读取 CA 私钥文件错误：", err)
			return
		}
		caKeyParsed, err := ParsePrivateKey(string(caKeyData))
		if err != nil {
			fmt.Println("解析 CA 私钥失败：", err)
			return
		}
		app.caCert = caCertParsed
		app.caKey = caKeyParsed
		keyPEM, _ := PrivateKeyToPEM(app.caKey)
		certPEM, _ := CertificateToPEM(app.caCert)
		app.attestation = &AndroidAttestation{
			Keyboxes: []Keybox{
				{
					DeviceID: "",
					Keys: []Key{
						{
							Algorithm:  "ecdsa",
							PrivateKey: PEMBlock{Format: "pem", Value: keyPEM},
							CertificateChain: &CertificateChain{
								NumberOfCertificates: 1,
								Certificates: []PEMBlock{
									{Format: "pem", Value: certPEM},
								},
							},
						},
					},
				},
			},
		}
		fmt.Println("成功导入 CA 数据")
	case *generateCASubject != "":
		parts := strings.Split(*generateCASubject, ":")
		subject := parts[0]
		caType := "ecdsa"
		if len(parts) > 1 {
			caType = strings.ToLower(parts[1])
		}
		var (
			certPEM, keyPEM string
			newCACert       *x509.Certificate
			newCAKey        interface{}
			err             error
		)
		if caType == "rsa" {
			certPEM, keyPEM, newCACert, newCAKey, err = GenerateSelfSignedCACertificateRSA(subject)
		} else {
			certPEM, keyPEM, newCACert, newCAKey, err = GenerateSelfSignedCACertificateECDSA(subject)
		}
		if err != nil {
			fmt.Printf("生成 %s CA 失败: %v\n", strings.ToUpper(caType), err)
			return
		}
		app.caCert = newCACert
		app.caKey = newCAKey
		app.attestation = &AndroidAttestation{
			Keyboxes: []Keybox{
				{
					DeviceID: "",
					Keys: []Key{
						{
							Algorithm:  caType,
							PrivateKey: PEMBlock{Format: "pem", Value: keyPEM},
							CertificateChain: &CertificateChain{
								NumberOfCertificates: 1,
								Certificates: []PEMBlock{
									{Format: "pem", Value: certPEM},
								},
							},
						},
					},
				},
			},
		}
		fmt.Printf("成功生成 %s CA\n", strings.ToUpper(caType))
	}

	if *generateSubCert {
		app.generateSubCert()
	}

	if *showAttestation {
		app.showAttestation()
	}

	if *verifyFlag {
		app.verifyAll()
	}

	if *saveFile != "" {
		if app.attestation == nil {
			fmt.Println("无 Attestation 数据可保存")
			return
		}
		if err := app.attestation.SaveToFile(*saveFile); err != nil {
			fmt.Println("保存 XML 失败：", err)
		} else {
			fmt.Println("成功保存到", *saveFile)
		}
		return
	}

	// 若无参数或部分参数未处理则进入交互模式
	app.RunInteractive()
}
