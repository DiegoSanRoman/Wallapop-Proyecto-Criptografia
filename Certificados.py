import os
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import time

def create_csr(private_key, common_name):
    """
    Creates a Certificate Signing Request (CSR) using the user's private key and public key.

    Args:
        private_key (rsa.RSAPrivateKey): The user's private key.
        public_key (rsa.RSAPublicKey): The user's public key.
        common_name (str): The common name for the CSR.

    Returns:
        bytes: The CSR in PEM format.
    """
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
    """
    Generates and saves a pair of RSA keys (private and public) for a user.

    Args:
        username (str): The username for whom the keys are generated.

    Returns:
        tuple: A tuple containing the private key and public key.
    """
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
    """
    Creates a Certificate Authority (CA) using OpenSSL.

    This function sets up the necessary directories and files, and generates a self-signed certificate for the CA.
    """
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
    """
    Creates a certificate for a user based on their CSR.

    Args:
        csr_pem (bytes): The CSR in PEM format (Solicitud de Firma de Certificado).
        username (str): The username for whom the certificate is created.
    """
    # Si el CSR es nulo o no válido, se imprime un mensaje de error y se sale de la función
    if not csr_pem:
        print(f"Error: No se pudo generar el CSR para el usuario {username}.")
        return

    # Ruta donde se guardará el CSR (en la carpeta "solicitudes")
    csr_path = os.path.abspath(os.path.join("Certificados", "solicitudes", f"{username}_csr.pem"))

    # Ruta donde se guardará el certificado final
    cert_path = os.path.abspath(os.path.join("Certificados", "nuevoscerts", f"{username}_cert.pem"))

    # Ruta del archivo de configuración OpenSSL
    openssl_config_path = os.path.abspath(os.path.join("openssl_AC1.cnf"))

    # Guardar el CSR en la ruta especificada
    with open(csr_path, "wb") as csr_file:
        csr_file.write(csr_pem)

    # Intentar verificar que el CSR se guardó correctamente (espera hasta 5 intentos)
    attempts = 0
    while not os.path.exists(csr_path) and attempts < 5:
        print(f"Esperando que el archivo CSR se cree correctamente: intento {attempts + 1}")
        time.sleep(1)  # Pausa de 1 segundo antes del siguiente intento
        attempts += 1

    # Si el archivo CSR no se creó tras varios intentos, se imprime un mensaje de error y se sale
    if not os.path.exists(csr_path):
        print(f"Error: El archivo CSR no se pudo crear en la ruta {csr_path} después de varios intentos.")
        return

    # Cambiar los permisos del archivo CSR para asegurarse de que es accesible
    os.chmod(csr_path, 0o644)
    time.sleep(2)  # Pausa breve para garantizar que los permisos se aplicaron

    # Rutas de la clave privada y el certificado de la CA (Autoridad Certificadora)
    ca_private_key_path = os.path.abspath(os.path.join("Certificados", "private", "ca1key.pem"))
    ca_cert_path = os.path.abspath(os.path.join("Certificados", "ac1cert.pem"))
    ca_dir = os.path.abspath("Certificados")

    # Leer y actualizar el archivo de configuración de OpenSSL con las rutas absolutas
    with open(openssl_config_path, "r") as file:
        config_data = file.read()
    config_data = config_data.replace("./private/ca1key.pem", ca_private_key_path)
    with open(openssl_config_path, "w") as file:
        file.write(config_data)

    # Establecer fechas de validez del certificado
    start_time = datetime.utcnow()  # Fecha de inicio: ahora
    end_time = start_time + timedelta(minutes=10/60)  # Fecha de expiración: 2 minutos después
    start_time_str = start_time.strftime("%Y%m%d%H%M%SZ")  # Formato para OpenSSL
    end_time_str = end_time.strftime("%Y%m%d%H%M%SZ")

    # Comando OpenSSL para firmar el CSR y crear el certificado
    cmd = (
        f"openssl ca -in {csr_path} -out {cert_path} -batch -notext -config {openssl_config_path} "
        f"-extensions usr_cert -utf8 -startdate {start_time_str} -enddate {end_time_str}"
    )

    try:
        # Ejecutar el comando con OpenSSL y verificar si se completa sin errores
        subprocess.run(cmd, shell=True, cwd=ca_dir, check=True)
    except subprocess.CalledProcessError as e:
        # Si ocurre un error, imprimir información para depuración
        print(f"Error al ejecutar el comando OpenSSL: {e}")
        print(f"Verifica la ruta del archivo de configuración: {openssl_config_path}")
    else:
        # Si todo fue exitoso, imprimir un mensaje de éxito
        print(f"Certificado creado exitosamente para el usuario {username}")

def generate_crl():
    # Definir rutas de archivos y directorios
    ca_dir = os.path.abspath("Certificados")
    ca_private_key_path = os.path.join(ca_dir, "private", "ca1key.pem")
    ca_cert_path = os.path.join(ca_dir, "ac1cert.pem")
    crl_path = os.path.join(ca_dir, "crls", "ca1crl.pem")
    openssl_config_path = os.path.abspath("openssl_AC1.cnf")

    # Crear directorio y archivo crlnumber si no existen
    os.makedirs(os.path.join(ca_dir, "crls"), exist_ok=True)
    crlnumber_path = os.path.join(ca_dir, "crlnumber")
    if not os.path.exists(crlnumber_path):
        with open(crlnumber_path, "w") as f:
            f.write("01\n")

    # Comando OpenSSL para generar la CRL
    cmd = (
        f"openssl ca -gencrl -keyfile {ca_private_key_path} -cert {ca_cert_path} "
        f"-out {crl_path} -config {openssl_config_path}"
    )

    try:
        # Ejecutar el comando OpenSSL
        result = subprocess.run(cmd, shell=True, cwd=ca_dir, check=True, capture_output=True, text=True)
        print(f"CRL generada y guardada en {crl_path}")
        print("Salida de OpenSSL:", result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Error al generar la CRL: {e}")
        print("Error de OpenSSL:", e.stderr)

def auto_update_crl():
    # Definir ruta del directorio de certificados
    certs_dir = os.path.join("Certificados", "nuevoscerts")
    try:
        while True:
            certs_to_revoke = []

            # Revisar todos los certificados válidos
            for cert_file in os.listdir(certs_dir):
                cert_path = os.path.join(certs_dir, cert_file)

                # Filtrar archivos no válidos
                if not cert_file.endswith("_cert.pem"):
                    print(f"Archivo {cert_file} ignorado.")
                    continue

                try:
                    # Leer y cargar el certificado
                    with open(cert_path, "rb") as f:
                        cert_data = f.read()

                    # Intentar cargar el archivo como certificado PEM
                    try:
                        cert = x509.load_pem_x509_certificate(cert_data)
                    except ValueError:
                        print(f"Archivo {cert_file} no es un certificado válido. Saltando...")
                        continue

                    # Normalizar fecha de expiración
                    cert_expiration = cert.not_valid_after.replace(tzinfo=timezone.utc)

                    # Verificar si ha expirado
                    if cert_expiration < datetime.now(timezone.utc):
                        print(f"Certificado {cert_file} ha expirado.")

                        # Verificar si ya está revocado
                        if not is_cert_revoked(cert):
                            print(f"Certificado {cert_file} será revocado.")
                            certs_to_revoke.append(cert_path)
                        else:
                            print(f"Certificado {cert_file} ya está revocado.")
                except Exception as e:
                    print(f"Error al procesar {cert_file}: {e}")

            # Revocar todos los certificados expirados
            for cert_path in certs_to_revoke:
                revoke_cert(cert_path)

            # Actualizar la CRL
            if certs_to_revoke:
                generate_crl()
            else:
                print("No hay certificados expirados para revocar.")

            time.sleep(10)

    except Exception as e:
        print(f"Error general al actualizar la CRL: {e}")

def revoke_cert(cert_path):
    # Definir rutas de archivos y directorios
    cert_path = os.path.abspath(cert_path)
    ca_dir = os.path.abspath("Certificados")
    openssl_config_path = os.path.abspath("openssl_AC1.cnf")

    if not os.path.exists(cert_path):
        print(f"Error: El archivo de certificado no existe - {cert_path}")
        return

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()

        try:
            cert = x509.load_pem_x509_certificate(cert_data)
        except ValueError:
            print(f"Error: El archivo {cert_path} no es un certificado válido.")
            return

        cert_serial = format(cert.serial_number, "X").upper()

        if is_cert_revoked(cert):
            print(f"Certificado {cert_serial} ya está revocado.")
            return

        cmd = f"openssl ca -revoke \"{cert_path}\" -config \"{openssl_config_path}\""
        result = subprocess.run(cmd, shell=True, cwd=ca_dir, check=True, capture_output=True, text=True)
        print(f"Certificado {cert_serial} revocado exitosamente.")
        print("Salida de OpenSSL:", result.stdout)
        generate_crl()

    except subprocess.CalledProcessError as e:
        print(f"Error al revocar el certificado: {e}")
        print("Error de OpenSSL:", e.stderr)

    except Exception as e:
        print(f"Error al procesar el certificado {cert_path}: {e}")

def is_cert_revoked(cert):
    # Definir ruta del archivo index.txt
    index_path = os.path.join("Certificados", "index.txt")

    if not os.path.exists(index_path):
        return False

    with open(index_path, "r") as f:
        lines = f.readlines()

    cert_serial = format(cert.serial_number, "X").zfill(2)

    for line in lines:
        if line.startswith("R") and cert_serial in line:
            return True

    return False

def main():
    create_ca()

    # Registro de Usuarios y Certificados
    usuarios = [
        {"username": "usuario1", "nombre": "Juan", "email": "juan@example.com"},
        {"username": "usuario2", "nombre": "Maria", "email": "maria@example.com"},
    ]

    for usuario in usuarios:
        username = usuario["username"]

        # Comprobar si ya existe el certificado
        cert_path = os.path.join("Certificados", "nuevoscerts", f"{username}_cert.pem")
        if os.path.exists(cert_path):
            print(f"El certificado para {username} ya existe. Saltando...")
            continue

        # Crear claves y certificado
        print(f"Registrando usuario: {username}")
        private_key, _ = save_key_pair(username)
        csr_pem = create_csr(private_key, username)
        create_cert(csr_pem, username)

    # Actualización Automática de CRL
    auto_update_crl()


if __name__ == "__main__":
    main()