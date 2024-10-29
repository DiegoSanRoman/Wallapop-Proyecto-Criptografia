# Proyecto Criptografia

## Descripción del Proyecto

El propósito principal de esta aplicación es proporcionar una plataforma para la compra y venta de productos de segunda mano, similar a servicios como Wallapop, de ahí el nombre de la aplicación. En este entorno, los usuarios pueden publicar productos para la venta, navegar por los productos disponibles, y realizar compras de manera segura. Además, los usuarios pueden enviar un mensaje al vendedor al solicitar la compra de uno de sus productos. De esta manera, el vendedor puede decidir si vender o no el producto a la persona que lo ha solicitado.

Además, la aplicación está centrada en la seguridad, proporcionando diversos sistemas de seguridad y autentificación que serán explicados más adelante durante esta primera parte de la práctica.

La aplicación también promueve la transparencia y la facilidad de uso, brindando a los usuarios interfaces sencillas y atractivas para gestionar sus productos, comunicarse con otros usuarios, y realizar compras. Esto mejora la experiencia de usuario, garantizando que tanto compradores como vendedores puedan utilizar la plataforma de manera eficiente.

## Estructura Interna

En lo que respecta a la estructura interna de nuestra aplicación, hemos desarrollado una página web utilizando la biblioteca Flask de Python. Para lograr esto, hemos definido varios archivos que componen la base del proyecto. La lógica de funcionamiento de la web se encuentra en el archivo `app.py`, donde hemos implementado todas las funcionalidades en Python. Además, hemos creado `Criptografia.py`, que contiene las funciones relacionadas con los procesos de criptografía necesarios para asegurar la información. El archivo `main.py` tiene la finalidad de ejecutar la aplicación web.

Dentro del directorio principal, también hemos incluido una carpeta llamada `basededatos`, que alberga todos los archivos relacionados con la gestión y funcionamiento de la base de datos, utilizando SQLAlchemy para la interacción con una base de datos relacional. Por otra parte, en la carpeta `templates`, se encuentran los archivos HTML que estructuran las distintas secciones de la página. Finalmente, la carpeta `static` contiene los archivos CSS y las imágenes que contribuyen a que la interfaz sea visualmente atractiva y fácil de usar para los visitantes de la web.

## Características

- Registro de usuarios con validación de fortaleza de contraseña.
- Inicio de sesión con hashing de contraseñas y autenticación de dos factores (2FA).
- Almacenamiento y recuperación segura de datos cifrados.
- Gestión de productos (compra y venta).
- Gestión de amigos.

## Prerrequisitos

- Python 3.x
- Flask
- Flask-SQLAlchemy
- Flask-Mail
- cryptography
- pycryptodome

## Instalación

1. **Clonar el repositorio:**

    ```bash
    git clone https://github.com/Diego100495878/Criptografia.git
    cd Criptografia
    ```

2. **Crear un entorno virtual y activarlo:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # En Windows usa `venv\Scripts\activate`
    ```

3. **Instalar los paquetes requeridos:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Configurar la base de datos:**

    ```bash
    flask db init
    flask db migrate -m "Initial migration."
    flask db upgrade
    ```

5. **Configurar Flask-Mail:**

    Actualiza la configuración del correo en `app.py` con tus credenciales de correo:

    ```python
    app.config['MAIL_USERNAME'] = 'tu_correo@gmail.com'
    app.config['MAIL_PASSWORD'] = 'tu_contraseña_de_correo'
    ```

## Ejecución de la Aplicación

1. **Iniciar el servidor de desarrollo de Flask:**

    ```bash
    flask run
    ```

2. **Abrir tu navegador web y navegar a:**

    ```
    http://127.0.0.1:5000/
    ```

## Uso

### Registro de Usuario

1. Ve a la página de registro haciendo clic en el enlace "Regístrate".
2. Completa el formulario de registro con tu nombre de usuario, contraseña, nombre, ciudad y correo electrónico.
3. Envía el formulario para crear una nueva cuenta.

### Inicio de Sesión

1. Ve a la página de inicio de sesión.
2. Ingresa tu nombre de usuario y contraseña.
3. Si las credenciales son correctas, se enviará un token 2FA a tu correo electrónico.
4. Ingresa el token 2FA para completar el proceso de inicio de sesión.

### Comprar un Producto

1. Navega a la página "Comprar".
2. Selecciona un producto que desees comprar.
3. Ingresa un mensaje para el vendedor y envía el formulario.
4. El estado del producto se actualizará a "pendiente de confirmación".

### Vender un Producto

1. Navega a la página "Vender".
2. Completa los detalles del producto (nombre, categoría, precio, descripción).
3. Envía el formulario para listar el producto en venta.

### Ver Perfil

1. Navega a la página "Perfil".
2. Visualiza tu información personal e historial de transacciones.

## Contribuir

1. Haz un fork del repositorio.
2. Crea una nueva rama (`git checkout -b feature-branch`).
3. Realiza tus cambios.
4. Haz commit de tus cambios (`git commit -m 'Añadir nueva característica'`).
5. Haz push a la rama (`git push origin feature-branch`).
6. Abre un pull request.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

## Contacto

Para cualquier pregunta o problema, por favor abre un issue en GitHub o contacta al propietario del repositorio.

## Integrantes
- Bárbara Sánchez Moratalla - 100495857
- Diego San Román Posada - 100495878
