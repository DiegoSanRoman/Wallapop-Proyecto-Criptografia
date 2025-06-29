# Proyecto Criptografia

Este repositorio contiene un proyecto desarrollado como trabajo de la asignatura **Criptografía y Seguridad Informática** de tercer curso de universidad. La aplicación resultante es una plataforma de compra y venta de productos de segunda mano centrada en la seguridad.

## Descripción del Proyecto

El objetivo es ofrecer un entorno similar a Wallapop donde los usuarios puedan publicar productos, buscar entre las ofertas disponibles y comunicarse de forma segura con los vendedores. Se implementan distintos mecanismos de seguridad para garantizar la integridad y confidencialidad de los datos durante el proceso de compra.

La interfaz se ha diseñado para ser sencilla de utilizar, facilitando tanto la gestión de productos como la interacción entre usuarios.

## Estructura del Proyecto

```
Criptografia/
├── app.py            # Lógica principal y rutas de la aplicación Flask
├── Criptografia.py   # Funciones de cifrado y utilidades criptográficas
├── main.py           # Script para lanzar la aplicación
├── basededatos/      # Ficheros y base de datos SQLite
│   ├── database.db
│   ├── database.py   # Script para inicializar la base de datos
│   └── database.sql  # Ejemplos y consultas
├── templates/        # Plantillas HTML de la web
├── static/           # Recursos estáticos: CSS, imágenes y JS
│   ├── styles/
│   ├── imagenes/
│   └── scripts/
└── Web/              # Archivos generados automáticamente (cache)
```

- **app.py** contiene todas las rutas de la aplicación, la definición de modelos de la base de datos y la configuración de Flask.
- **Criptografia.py** agrupa las funciones que manejan el cifrado y la verificación de contraseñas, así como el envío de tokens por correo.
- **main.py** es un pequeño script que importa la aplicación desde `app.py` y la ejecuta.
- **basededatos/** almacena la base de datos SQLite y un script para crearla o actualizarla.
- **templates/** incluye las vistas HTML que conforman las distintas páginas (registro, login, compra, venta, etc.).
- **static/** alberga hojas de estilo, scripts de cliente e imágenes usadas por las plantillas.

## Características Principales

- Registro de usuarios con validación de fortaleza de contraseña.
- Inicio de sesión con hashing de contraseñas y verificación en dos pasos (2FA).
- Almacenamiento cifrado de la información sensible.
- Gestión de productos: compra, venta y seguimiento de pedidos.
- Sistema de amistades entre usuarios.

## Requisitos Previos

- Python 3.x
- [Flask](https://flask.palletsprojects.com/)
- Flask-SQLAlchemy
- Flask-Mail
- cryptography
- pycryptodome

## Instalación

1. **Clona el repositorio:**

   ```bash
   git clone https://github.com/Diego100495878/Criptografia.git
   cd Criptografia
   ```
2. **Crea y activa un entorno virtual (opcional pero recomendado):**

   ```bash
   python -m venv venv
   source venv/bin/activate  # En Windows: venv\Scripts\activate
   ```
3. **Instala las dependencias:**

   ```bash
   pip install -r requirements.txt
   ```
   *(Si no existe `requirements.txt`, instala los paquetes listados en la sección anterior manualmente.)*

## Ejecución de la Aplicación

1. Inicializa la base de datos si es necesario ejecutando:

   ```bash
   python basededatos/database.py
   ```
2. Lanza el servidor de desarrollo de Flask:

   ```bash
   flask run
   ```
3. Abre tu navegador y accede a `http://127.0.0.1:5000/` para empezar a usar la aplicación.

## Uso Básico

### Registro de Usuario

1. Accede a la página de registro desde la portada.
2. Introduce un nombre de usuario, contraseña, nombre real, ciudad y correo electrónico.
3. Tras enviar el formulario recibirás un correo para confirmar la operación.

### Inicio de Sesión

1. Introduce tus credenciales en la página de acceso.
2. Recibirás un token 2FA por email que deberás escribir para completar el login.

### Compra y Venta

- Desde la sección **Comprar** puedes buscar productos y solicitar la compra, enviando un mensaje cifrado al vendedor.
- En **Vender** puedes añadir nuevos artículos especificando su nombre, categoría, precio y descripción.
- El apartado **Perfil** muestra tu información y el historial de operaciones realizadas.

## Contribuir

1. Haz un fork del repositorio.
2. Crea una rama para tus cambios: `git checkout -b mi-rama`.
3. Realiza las modificaciones y sube la rama: `git push origin mi-rama`.
4. Abre un Pull Request en GitHub.

## Contacto

Si encuentras problemas o tienes dudas, abre un issue en GitHub o contacta con los responsables del proyecto.

## Integrantes

- Bárbara Sánchez Moratalla - 100495857@alumnos.uc3m.es
- Diego San Román Posada - 100495878@alumnos.uc3m.es
