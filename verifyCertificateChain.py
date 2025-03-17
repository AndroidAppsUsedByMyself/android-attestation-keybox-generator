import xml.etree.ElementTree as ET
import base64
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

def extract_certificates_and_key_from_keybox(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        certificates = []
        private_key_pem = None
        
        for cert_elem in root.findall('.//CertificateChain/Certificate'):
            cert_pem = cert_elem.text.strip().replace("&#xA;", "\n")
            certificates.append(cert_pem)
        
        private_key_elem = root.find('.//PrivateKey')
        if private_key_elem is not None:
            private_key_pem = private_key_elem.text.strip().replace("&#xA;", "\n")
        
        return certificates, private_key_pem
    except Exception as e:
        print(f"解析 keybox.xml 时出错: {e}")
        sys.exit(1)

def verify_certificate_chain(cert_pem_list):
    cert_chain = []
    for cert_pem in cert_pem_list:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_chain.append(cert)
    
    broken_links = 0
    
    for i in range(len(cert_chain) - 1):
        cert = cert_chain[i]
        issuer_cert = cert_chain[i + 1]
        
        print(f"验证证书 {i}:")
        print(f"  主题 (Subject): {cert.subject}")
        print(f"  颁发者 (Issuer): {cert.issuer}")
        print(f"验证证书 {i+1}:")
        print(f"  主题 (Subject): {issuer_cert.subject}")
        print(f"  颁发者 (Issuer): {issuer_cert.issuer}")
        
        if cert.issuer != issuer_cert.subject:
            print(f"[破坏] 证书 {i} 颁发者与证书 {i+1} 主题不匹配")
            broken_links += 1
            continue
        
        issuer_public_key = issuer_cert.public_key()
        try:
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
            print(f"[成功] 证书 {i} 由证书 {i+1} 成功验证")
        except Exception as e:
            print(f"[破坏] 证书 {i} 无法由证书 {i+1} 验证: {e}")
            broken_links += 1
    
    if broken_links == 0:
        print("证书链验证成功")
    else:
        print(f"证书链中发现 {broken_links} 处破坏")

def verify_key_certificate_pair(cert_pem, private_key_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    private_key = None
    
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    except Exception as e:
        print(f"[错误] 无法加载私钥: {e}")
        return
    
    if private_key.public_key().public_numbers() != cert.public_key().public_numbers():
        print("[破坏] 证书的公钥与提供的私钥不匹配")
    else:
        print("[成功] 证书和密钥匹配")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python main.py keybox.xml")
        sys.exit(1)
    
    keybox_file = sys.argv[1]
    certs, private_key_pem = extract_certificates_and_key_from_keybox(keybox_file)
    verify_certificate_chain(certs)
    
    if private_key_pem:
        verify_key_certificate_pair(certs[0], private_key_pem)
    else:
        print("未找到私钥")
