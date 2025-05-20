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
	"path/filepath"
	"strings"
	"time"
)

// ----------------------- XML 数据结构定义 -----------------------

type AndroidAttestation struct {
	XMLName          xml.Name `xml:"AndroidAttestation"`
	NumberOfKeyboxes int      `xml:"NumberOfKeyboxes"`
	Keyboxes         []Keybox `xml:"Keybox"`
}

type Keybox struct {
	DeviceID string `xml:"DeviceID,attr"`
	Keys     []Key  `xml:"Key"`
}

type Key struct {
	Algorithm        string            `xml:"algorithm,attr"`
	PrivateKey       PEMBlock          `xml:"PrivateKey"`
	CertificateChain *CertificateChain `xml:"CertificateChain,omitempty"`
}

type PEMBlock struct {
	Format string `xml:"format,attr"`
	Value  string `xml:",chardata"`
}

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

func ParseCertificate(pemStr string) (*x509.Certificate, error) {
	pemStr = cleanupPEM(pemStr)
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("解析证书 PEM 数据失败")
	}
	return x509.ParseCertificate(block.Bytes)
}

func CertificateToPEM(cert *x509.Certificate) (string, error) {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return string(pem.EncodeToMemory(block)), nil
}

// ----------------------- 证书生成函数 -----------------------

func GenerateSubordinateCertificate(parentCert *x509.Certificate, parentKey interface{}, subject string, algo string) (string, string, error) {
	switch strings.ToLower(algo) {
	case "ecdsa":
		return GenerateSubordinateCertificateECDSA(parentCert, parentKey, subject)
	case "rsa":
		return GenerateSubordinateCertificateRSA(parentCert, parentKey, subject)
	default:
		return "", "", errors.New("不支持的算法")
	}
}

func generateSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func createCertTemplate(serial *big.Int, subject string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func GenerateSubordinateCertificateECDSA(parentCert *x509.Certificate, parentKey interface{}, subject string) (string, string, error) {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := generateSerial()
	if err != nil {
		return "", "", err
	}
	template := createCertTemplate(serial, subject)
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
	serial, err := generateSerial()
	if err != nil {
		return "", "", err
	}
	template := createCertTemplate(serial, subject)
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, &newKey.PublicKey, parentKey)
	if err != nil {
		return "", "", err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
	keyBytes := x509.MarshalPKCS1PrivateKey(newKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))
	return certPEM, keyPEM, nil
}

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
	tempDir     string
	stepCounter int
}

func NewApp() *App {
	tempDir, err := os.MkdirTemp("", "keybox_temp")
	if err != nil {
		fmt.Println("创建临时目录失败：", err)
		os.Exit(1)
	}
	return &App{
		reader:      bufio.NewReader(os.Stdin),
		tempDir:     tempDir,
		stepCounter: 0,
	}
}

func (app *App) saveIntermediate() {
	if app.attestation == nil {
		return
	}
	app.stepCounter++
	filename := filepath.Join(app.tempDir, fmt.Sprintf("keybox_step%d.xml", app.stepCounter))
	if err := app.attestation.SaveToFile(filename); err != nil {
		fmt.Println("保存中间文件失败：", err)
	} else {
		fmt.Println("保存中间文件到", filename)
	}
}

func (app *App) RunInteractive() {
	fmt.Println("临时目录：", app.tempDir)
	fmt.Println("临时目录将保留，可手动删除")
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
		app.saveIntermediate()
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
	err = app.importCANonInteractive(certFile, keyFile)
	if err != nil {
		fmt.Println("导入 CA 失败：", err)
	} else {
		app.saveIntermediate()
	}
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
	err = app.generateCANonInteractive(subject, caType)
	if err != nil {
		fmt.Println("生成 CA 失败：", err)
	} else {
		app.saveIntermediate()
	}
}

func (app *App) generateSubCert() {
	if app.attestation == nil {
		fmt.Println("请先加载/生成 Attestation 数据！")
		return
	}
	subject, err := readLine("请输入 Subject: ", app.reader)
	if err != nil {
		fmt.Println("读取错误：", err)
		return
	}
	subAlg, err := readLine("请选择下一级证书算法 (ecdsa/rsa): ", app.reader)
	if err != nil {
		fmt.Println("读取错误：", err)
		return
	}
	err = app.generateSubCertNonInteractive(subject, subAlg)
	if err != nil {
		fmt.Println("生成子证书失败：", err)
	} else {
		app.saveIntermediate()
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
	fmt.Println("临时目录保留，可手动删除：", app.tempDir)
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

// ----------------------- 非交互式支持函数 -----------------------

func (app *App) importCANonInteractive(certFile, keyFile string) error {
	caCertData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("读取 CA 证书文件错误：%v", err)
	}
	caCertParsed, err := ParseCertificate(string(caCertData))
	if err != nil {
		return fmt.Errorf("解析 CA 证书失败：%v", err)
	}
	caKeyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("读取 CA 私钥文件错误：%v", err)
	}
	caKeyParsed, err := ParsePrivateKey(string(caKeyData))
	if err != nil {
		return fmt.Errorf("解析 CA 私钥失败：%v", err)
	}
	app.caCert = caCertParsed
	app.caKey = caKeyParsed
	keyPEM, _ := PrivateKeyToPEM(app.caKey)
	certPEM, _ := CertificateToPEM(app.caCert)
	algo := "ecdsa"
	if _, ok := app.caKey.(*rsa.PrivateKey); ok {
		algo = "rsa"
	}
	app.attestation = &AndroidAttestation{
		Keyboxes: []Keybox{
			{
				DeviceID: "",
				Keys: []Key{
					{
						Algorithm:  algo,
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
	return nil
}

func (app *App) generateCANonInteractive(subject, caType string) error {
	var (
		certPEM, keyPEM string
		newCACert       *x509.Certificate
		newCAKey        interface{}
		err             error
	)
	caType = strings.ToLower(caType)
	if caType == "rsa" {
		certPEM, keyPEM, newCACert, newCAKey, err = GenerateSelfSignedCACertificateRSA(subject)
	} else {
		certPEM, keyPEM, newCACert, newCAKey, err = GenerateSelfSignedCACertificateECDSA(subject)
		caType = "ecdsa"
	}
	if err != nil {
		return fmt.Errorf("生成 %s CA 失败: %v", strings.ToUpper(caType), err)
	}
	app.caCert = newCACert
	app.caKey = newCAKey
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
	fmt.Printf("成功生成 %s CA\n", strings.ToUpper(caType))
	return nil
}

func (app *App) generateSubCertNonInteractive(subject, algo string) error {
	if app.attestation == nil {
		return errors.New("请先加载/生成 Attestation 数据")
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
			newCertPEM, newKeyPEM, err := GenerateSubordinateCertificate(parentCert, parentKey, subject, algo)
			if err != nil {
				fmt.Printf("Keybox %d Key %d: 生成下一级证书失败: %v\n", kbIndex, keyIndex, err)
				continue
			}
			key.CertificateChain.Certificates = append([]PEMBlock{{Format: "pem", Value: newCertPEM}}, key.CertificateChain.Certificates...)
			key.CertificateChain.NumberOfCertificates = len(key.CertificateChain.Certificates)
			key.PrivateKey.Value = newKeyPEM
			key.Algorithm = strings.ToLower(algo)
			app.attestation.Keyboxes[kbIndex].Keys[keyIndex] = key
			fmt.Printf("Keybox %d Key %d: 成功生成下一级证书\n", kbIndex, keyIndex)
		}
	}
	return nil
}

// ----------------------- 命令行参数处理 -----------------------

func printUsage() {
	exeFile := filepath.Base(os.Args[0])
	usage := `用法:
  %s -interactive                进入交互模式
  或使用以下非交互式命令（支持操作序列）：
    -importAttestation <file>          从指定 XML 文件导入 Attestation 数据
    -importCA <certFile> <keyFile>     导入 CA 证书及私钥（PEM 格式）
    -generateCA <subject> [caType]     根据 subject 生成自签 CA (caType 可选 ecdsa/rsa，默认 ecdsa)
    -generateSubCert <subject> <algo>  生成下一级证书 (algo: ecdsa/rsa)
    -showAttestation                   显示当前 Attestation 信息
    -save <outfile>                    保存 Attestation 数据到 outfile
    -verify                            验证证书链和密钥对

示例：
  %s -importAttestation keybox.xml.1 -generateSubCert mysubject ecdsa -showAttestation
  %s -importAttestation keybox.xml.1 -generateSubCert mysubject ecdsa -save keybox.xml.1
  %s -importAttestation keybox.xml.1 -generateSubCert mysubject ecdsa -generateSubCert mysubject2 ecdsa -save keybox.xml.1
`
	fmt.Printf(usage, exeFile, exeFile, exeFile, exeFile)
}

func processOperations(args []string) {
	app := NewApp()
	fmt.Println("临时目录：", app.tempDir)
	defer func() {
		fmt.Println("临时目录保留，可手动删除：", app.tempDir)
	}()

	step := 0
	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "-importAttestation":
			if i+1 >= len(args) {
				fmt.Println("Error: missing file path for -importAttestation")
				return
			}
			filePath := args[i+1]
			a, err := LoadAttestationFromFile(filePath)
			if err != nil {
				fmt.Println("加载 XML 失败：", err)
				return
			}
			app.attestation = a
			fmt.Println("成功加载 Attestation 数据")
			app.saveIntermediate()
			i += 2
		case "-importCA":
			if i+2 >= len(args) {
				fmt.Println("Error: missing certFile and keyFile for -importCA")
				return
			}
			certFile := args[i+1]
			keyFile := args[i+2]
			err := app.importCANonInteractive(certFile, keyFile)
			if err != nil {
				fmt.Println("导入 CA 失败：", err)
				return
			}
			app.saveIntermediate()
			i += 3
		case "-generateCA":
			if i+1 >= len(args) {
				fmt.Println("Error: missing subject for -generateCA")
				return
			}
			subject := args[i+1]
			caType := "ecdsa"
			if i+2 < len(args) && !strings.HasPrefix(args[i+2], "-") {
				caType = args[i+2]
				i++
			}
			err := app.generateCANonInteractive(subject, caType)
			if err != nil {
				fmt.Println("生成 CA 失败：", err)
				return
			}
			app.saveIntermediate()
			i += 2
		case "-generateSubCert":
			if i+2 >= len(args) {
				fmt.Println("Error: missing subject and algorithm for -generateSubCert")
				return
			}
			subject := args[i+1]
			algo := args[i+2]
			err := app.generateSubCertNonInteractive(subject, algo)
			if err != nil {
				fmt.Println("生成子证书失败：", err)
				return
			}
			app.saveIntermediate()
			i += 3
		case "-showAttestation":
			app.showAttestation()
			i++
		case "-save":
			if i+1 >= len(args) {
				fmt.Println("Error: missing file path for -save")
				return
			}
			filePath := args[i+1]
			if app.attestation == nil {
				fmt.Println("无 Attestation 数据可保存")
				return
			}
			if err := app.attestation.SaveToFile(filePath); err != nil {
				fmt.Println("保存 XML 失败：", err)
			} else {
				fmt.Println("成功保存到", filePath)
			}
			i += 2
		case "-verify":
			app.verifyAll()
			i++
		default:
			fmt.Println("未知操作：", arg)
			return
		}
		step++
	}
}

func main() {
	if len(os.Args) == 1 {
		printUsage()
		return
	}
	app := NewApp()
	if os.Args[1] == "-interactive" {
		app.RunInteractive()
	} else {
		processOperations(os.Args[1:])
	}
}
