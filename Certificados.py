import os
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import time

def create_csr(private_key, public_key, common_name):
    # Crear CSR usando la clave privada del usuario y la clave pública
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    csr = builder.sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem

def save_key_pair(username):
    # Crear directorio para guardar las claves si no existe
    os.makedirs(os.path.join("Certificados", "Claves"), exist_ok=True)

    # Generar un par de claves para el usuario
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serializar y guardar la clave privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_path = os.path.join("Certificados", "Claves", f"{username}_priv.pem")
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(private_pem)

    # Serializar y guardar la clave pública
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_path = os.path.join("Certificados", "Claves", f"{username}_pub.pem")
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(public_pem)

    return private_key, public_key

def create_ca():
    # Crear directorio para certificados de usuarios

    # Crear una autoridad certificadora (AC) usando OpenSSL
    ca_dir = os.path.join("Certificados")
    ca_private_key_path = os.path.abspath(os.path.join(ca_dir, "private", "ca1key.pem"))
    ca_cert_path = os.path.abspath(os.path.join(ca_dir, "ac1cert.pem"))

    # Crear directorios si no existen
    os.makedirs(os.path.join(ca_dir, "solicitudes"), exist_ok=True)
    os.makedirs(os.path.join(ca_dir, "crls"), exist_ok=True)
    os.makedirs(os.path.join(ca_dir, "nuevoscerts"), exist_ok=True)
    os.makedirs(os.path.join(ca_dir, "private"), exist_ok=True)

    # Crear e inicializar los ficheros necesarios
    if not os.path.exists(os.path.join(ca_dir, "serial")):
        with open(os.path.join(ca_dir, "serial"), "w") as serial_file:
            serial_file.write("01\n")
    if not os.path.exists(os.path.join(ca_dir, "index.txt")):
        with open(os.path.join(ca_dir, "index.txt"), "w") as index_file:
            index_file.write("")

    # Crear la clave privada y el certificado autofirmado para la AC, rellenando la información automáticamente
    if not os.path.exists(ca_private_key_path) or not os.path.exists(ca_cert_path):
        cmd = (
            f"openssl req -x509 -newkey rsa:2048 -days 360 -keyout {ca_private_key_path} "
            f"-out {ca_cert_path} -nodes "
            f"-subj \"/C=ES/ST=Madrid/L=Madrid/O=UC3M/CN=AC1\""
        )
        subprocess.run(cmd, shell=True, cwd=ca_dir)
        print("Autoridad Certificadora creada exitosamente")
    else:
        print("La Autoridad Certificadora ya existe.")

def create_cert(csr_pem, username):
    if not csr_pem:
        print(f"Error: No se pudo generar el CSR para el usuario {username}.")
        return

    csr_path = os.path.abspath(os.path.join("Certificados", "Claves", f"{username}_csr.pem"))
    cert_path = os.path.abspath(os.path.join("Certificados", "nuevoscerts", f"{username}_cert.pem"))
    openssl_config_path = os.path.abspath(os.path.join("openssl_AC1.cnf"))

    with open(csr_path, "wb") as csr_file:
        csr_file.write(csr_pem)

    attempts = 0
    while not os.path.exists(csr_path) and attempts < 5:
        print(f"Esperando que el archivo CSR se cree correctamente: intento {attempts + 1}")
        time.sleep(1)
        attempts += 1

    if not os.path.exists(csr_path):
        print(f"Error: El archivo CSR no se pudo crear en la ruta {csr_path} después de varios intentos.")
        return

    os.chmod(csr_path, 0o644)
    time.sleep(2)

    ca_private_key_path = os.path.abspath(os.path.join("Certificados", "private", "ca1key.pem"))
    ca_cert_path = os.path.abspath(os.path.join("Certificados", "ac1cert.pem"))
    ca_dir = os.path.abspath("Certificados")

    with open(openssl_config_path, "r") as file:
        config_data = file.read()
    config_data = config_data.replace("./private/ca1key.pem", ca_private_key_path)
    with open(openssl_config_path, "w") as file:
        file.write(config_data)

    start_time = datetime.utcnow()
    end_time = start_time + timedelta(minutes=2)
    start_time_str = start_time.strftime("%Y%m%d%H%M%SZ")
    end_time_str = end_time.strftime("%Y%m%d%H%M%SZ")

    cmd = (
        f"openssl ca -in {csr_path} -out {cert_path} -batch -notext -config {openssl_config_path} "
        f"-extensions usr_cert -utf8 -startdate {start_time_str} -enddate {end_time_str}"
    )
    try:
        subprocess.run(cmd, shell=True, cwd=ca_dir, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando OpenSSL: {e}")
        print(f"Verifica la ruta del archivo de configuración: {openssl_config_path}")
    else:
        print(f"Certificado creado exitosamente para el usuario {username}")

def main():
    # Crear la CA usando OpenSSL
    create_ca()

    # Simulación del registro de un nuevo usuario
    username = "usuario3"
    private_key, public_key = save_key_pair(username)

    # Crear CSR
    csr_pem = create_csr(private_key, public_key, username)

    # Crear el certificado
    create_cert(csr_pem, username)

if __name__ == "__main__":
    main()
