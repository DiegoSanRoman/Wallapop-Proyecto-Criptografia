# Proyecto de Criptografía y seguridad informática
Este proyecto se basa en una aplicación local que replica la manera de 
actuar de webs y aplicaciones como Wallapop, Vibbo, etc.

## Integrantes
- Bárbara Sánchez Moratalla - 100495857
- Diego San Román Posada - 100495878

## Requisitos

Para ejecutar este proyecto, necesitarás:

- Python 3.8 o superior
- PyCharm 2023.3.4 o cualquier otro IDE compatible

## Descripción del Proyecto

Este proyecto es una aplicación local que replica la funcionalidad de plataformas de venta en línea como Wallapop y Vibbo. Los usuarios pueden registrarse, iniciar sesión, comprar y vender artículos. Los datos de los usuarios y los artículos se almacenan en archivos JSON. La aplicación está escrita en Python y utiliza la biblioteca Tkinter para la interfaz gráfica de usuario.

## Uso

Para usar la aplicación, primero debes registrarte proporcionando un nombre de usuario y una contraseña. Una vez registrado, puedes iniciar sesión con tus credenciales.

En la pantalla principal, tendrás la opción de comprar o vender artículos. Si eliges comprar, se te mostrará una lista de todos los artículos disponibles. Puedes seleccionar un artículo de la lista para comprarlo.

Si eliges vender, se te pedirá que ingreses el nombre y el precio del artículo que deseas vender. Una vez que hayas proporcionado esta información, tu artículo se agregará a la lista de artículos disponibles para comprar.

Para cerrar la aplicación, simplemente cierra la ventana de la aplicación.

## Para barbara como usar lo de sqlite3
el database.db se encuentra en la carpeta database, para poder usarlo en la aplicación, se debe de cambiar la variable `database` en el archivo `main.py` a la ruta donde se encuentra el archivo `database.db` en tu computadora.

luego en databse.sql es lo que haciamos de sql en ficheros y tal, ahi escribes sio queires crear una tabla o algo (y comenta lo que no quieres que pase que la liamos)

despues, para ejecutarlo, te pones en database.py y lo runeas, y ya esta
