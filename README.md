INTRODUCCIÓN
==============
    TODO  

INSTALACIÓN RÁPIDA (recomendado)
==============
Usuarios windows 10 y 11:  
- Descarga el archivo 'install.ps1' en tu ordenador y búscalo con el explorador de archivos  
- Click derecho sobre el archivo -> ejecutar con Powershell. Se iniciará el instalador y ejecutará automáticamente las siguientes tareas:
    - Descargará los archivos necesarios en C:\Usuarios\Público\astroReport
    - Importará en el registro de windows la configuración necesaria para que astroReport aparezca en el menú contextual del explorador de archivos
    - NOTA: si no puedes ejecutar el archivo ps1, abre un Powershell como administrador y ejecuta: 
        - Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
        - Acepta con 'Y'
        - Si quieres, una vez instalado astroReport vuelve a habilitar esta opción



INSTALACIÓN MANUAL (no recomendado)
==============
- Instalar Python >= 3.12
- Cree un nuevo entorno virtual y actívelo (asegúrese de que está ejecutando python v3 y no v2):

        $ python -m venv whatsup_venv
        # usuarios linux:

                $ source astroReport_env/bin/activate

        # usuarios de windows:
                # si usa powershell

                        $ astroReport_env\Scripts\Activate.ps1

                # si utiliza un símbolo del sistema normal

                        $ astroReport_env\Scripts\activate.bat

- Instale las librerías python en su nuevo entorno virtual

        $ pip install -r requirements.txt


USO
==============
TODO

Click derecho sobre una carpeta con los fits -> astroReport

ARCHIVO DE CONFIGURACIÓN
==============
TODO
