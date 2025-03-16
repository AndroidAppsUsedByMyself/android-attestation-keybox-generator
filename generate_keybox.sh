#!/usr/bin/env bash

DEVICE_ID="Device-$(openssl rand -hex 8)"
TITLE="TEE"

CA_KEY="ca.key"
CA_CRT="ca.crt"
DEVICE_KEY="device.key"
DEVICE_CSR="device.csr"
DEVICE_CRT="device.crt"
KEYBOX_XML="keybox.xml"

# 生成 CA 私钥和自签名证书（有效期 10 年）
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out $CA_KEY
openssl req -key $CA_KEY -new -x509 -days 3650 -subj "/CN=My Root CA/title=$TITLE" -out $CA_CRT

# 生成设备私钥和 CSR（证书签名请求）
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out $DEVICE_KEY
openssl req -new -key $DEVICE_KEY -subj "/CN=My Device/title=$TITLE" -out $DEVICE_CSR

# 由 CA 签署设备证书（有效期 1 年）
openssl x509 -req -in $DEVICE_CSR -CA $CA_CRT -CAkey $CA_KEY -CAcreateserial -days 365 -out $DEVICE_CRT

# 读取私钥和证书内容，并保留格式
DEVICE_KEY_PEM=$(awk '{print "                "$0}' $DEVICE_KEY)
DEVICE_CRT_PEM=$(awk '{print "                    "$0}' $DEVICE_CRT)

cat > $KEYBOX_XML <<EOF
<?xml version="1.0"?>
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox DeviceID="$DEVICE_ID">
        <Key algorithm="ecdsa">
            <PrivateKey format="pem">
$DEVICE_KEY_PEM
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>1</NumberOfCertificates>
                <Certificate format="pem">
$DEVICE_CRT_PEM
                </Certificate>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>
EOF

echo "Keybox 文件已生成: $KEYBOX_XML"
