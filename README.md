INTRODUCCIÓN
==============
    TODO  

Analiza el contenido de un directorio y haz un resumen de los fits encontrados

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

Usuarios linux:
- Descarga el binario 'astroReport' de 'binaries' y el archivo de config 'astroReport.config.xml'


INSTALACIÓN MANUAL (no recomendado; no necesario)
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

Si eres un usuario de windows y has usado el método rápido de instalación, sólo tienes que hacer click derecho sobre una carpeta con los fits -> astroReport  
En cualquier caso se puede ejecutar desde la línea de comandos pasando como parámetro obligatorio el directorio (o varios) que quieres analizar  

ARCHIVO DE CONFIGURACIÓN DE PROYECTOS
==============
    TODO

astroReportProjectInfo.xml.example: renombra a astroReportProjectInfo.xml y cópialo al directorio que quieres analizar. Modifica dicho archivo según tu proyecto

ARCHIVO DE CONFIGURACIÓN GENERAL
==============
    TODO
