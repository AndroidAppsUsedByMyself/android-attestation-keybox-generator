**项目需求文档**

**项目名称**: Android Attestation Keybox Generator

**项目描述**:
本项目使用 Go 语言开发一个 Android 设备认证密钥箱（Keybox）生成器，采用面向对象编程思想，以 keybox 为核心，实现一系列密钥和证书的管理与操作。

---

**功能需求**:

0. **面向对象编程**:

   - 采用面向对象的方式设计 keybox 及相关组件。

1. **输入要求**:
   1.1. 输入可以是 `keybox.xml`（导入现有证书链和密钥进行生成操作）。 1.2. 输入可以是 CA 密钥（通过现有 CA 密钥生成 Keybox）。 1.3. 输入为空时，可选择自动生成 CA 密钥。

2. **证书与密钥生成**:
   2.1. 支持生成下一级证书和密钥，可多次执行此操作以形成完整的证书链。

3. **反解析到 keybox.xml**:

   - 在 Keybox 中，对于任何一个 Key，导出最后一个密钥（设备私钥 `PrivateKey`）和验证证书链 `CertificateChain`。

4. **密钥链认证**:

   - 支持对指定的 `keybox.xml` 进行密钥链认证，验证密钥链的完整性和有效性。

5. **菜单操作模式**:

   - 提供交互式菜单操作方式，方便用户管理和生成 Keybox。

6. **纯指令操作模式**:

7. **操作完成后保存**:

   - 进行任何操作后，支持将数据反解析并保存到 `keybox.xml`。

8. **文件处理方式**:

   - 尽量少使用已经弃用的库
   - 不使用已弃用的 `ioutil`，使用 `os` 进行文件处理。

---

**附录：Keybox 示例（一级证书，CA 作为设备密钥）**

```xml
<?xml version="1.0"?>
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="{0}">
    <Key algorithm="ecdsa">
      <PrivateKey format="pem">
        {1}
      </PrivateKey>
      <CertificateChain>
        <NumberOfCertificates>1</NumberOfCertificates>
        <Certificate format="pem">
          {2}
        </Certificate>
      </CertificateChain>
    </Key>
    <Key algorithm="rsa">
      <PrivateKey format="pem">
        {3}
      </PrivateKey>
    </Key>
  </Keybox>
</AndroidAttestation>
```

---

**开发技术栈**:

- 语言: Go
- XML 解析: `encoding/xml`
- 文件操作: `os`
- 证书和密钥管理: `crypto/x509`, `crypto/rsa`, `crypto/ecdsa`
