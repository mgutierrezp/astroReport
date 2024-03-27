INTRODUCCIÓN
==============
En una sesión de astrofotografía es muy común tirar a varios objetos una misma noche. Si son varias noches las que tiras, te puedes encontrar con varias carpetas cada una de ellas conteniendo al mismo tiempo varios objetos, tal que así:

    2024-02-03
        ---> M_42
        ---> IC_434
        ---> M_94
    2024-02-04
        ---> M_42
        ---> M_51
        ---> M_94
    2024-02-05
        ---> M_42
        ---> M_58
        ---> M_51

Después yo al menos en mi caso tengo un directorio para cada objeto, enlazando las sesiones con los directorios correspondientes:

    M_42
        ---> SESSION_01 (enlace a 2024-02-03)
        ---> SESSION_02 (enlace a 2024-02-04)
        ---> SESSION_03 (enlace a 2024-02-05)
    IC_434
        ---> SESSION_01 (enlace a 2024-02-03)
    M_94
        ---> SESSION_01 (enlace a 2024-02-03)
        ---> SESSION_02 (enlace a 2024-02-04)
    M_58
        ---> SESSION_01 (enlace a 2024-02-05)
    M_51
        ---> SESSION_01 (enlace a 2024-02-04)
        ---> SESSION_02 (enlace a 2024-02-05)

Así, cada vez que tiro a un objeto lo enlazo con la sesión correspondiente.  

La idea es que astroReport analice uno de los directorios del objeto (M_42, por ejemplo; un proyecto) y me haga un resumen de todos los lights clasificado por filtros y tiempo acumulado en las distintas sesiones y que, según la configuración del proyecto, me calcule los lights que quedan por hacer de cada filtro.  

Puede crear también las secuencias correspondientes para ekos y generar también un schedule para importarlo directamente en el secuenciador.

Si usas astrobin, astroReport también puede generar la secuencia de filtros en formato csv para que puedas copiar y pegar directamente en astrobin las distintas sesiones. 

astroReport usa las cabeceras fits (FILTER, GAIN, etc) de los archivos para el análisis y clasificación. Por lo tanto, éstas deben de estar correctamente definidas por el programa de adquisición. De lo contrario, puede dar resultados poco coherentes

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
- Descarga el binario 'astroReport' de 'binaries', el archivo de config 'astroReport.config.xml' y 'ekosTemplates' en el mismo directorio


INSTALACIÓN MANUAL (no recomendado; no necesario)
==============
- Instalar Python >= 3.12
- Cree un nuevo entorno virtual y actívelo (asegúrese de que está ejecutando python v3 y no v2):

        $ python -m venv astroReport_venv
        # usuarios linux:

                $ source astroReport_env/bin/activate

        # usuarios de windows:
                # si usa powershell

                        $ astroReport_env\Scripts\Activate.ps1

                # si utiliza un símbolo del sistema normal

                        $ astroReport_env\Scripts\activate.bat

- Instale las librerías python en su nuevo entorno virtual

        $ pip install -r requirements.txt

- Descarga el archivo de config 'astroReport.config.xml' y 'ekosTemplates' en el mismo directorio

USO
==============
Si eres un usuario de windows y has usado el método rápido de instalación, sólo tienes que hacer click derecho sobre una carpeta con los fits -> astroReport  
Los usuarios de linux también pueden hacer lo mismo pero el procedimiento depende de la distribución y el administrador de archivo que uses. En nemo, por ejemplo, basta con crear la acción correspondient en ~/.local/share/nemo/actions  
En cualquier caso se puede ejecutar desde la línea de comandos pasando como parámetro obligatorio el directorio (o varios) que quieres analizar  

    usage: astroReport.py

    positional arguments:
        dirs

    options:
        -h, --help            show this help message and exit
        -v                    write some debug info
        -V, --version         show program's version number and exit
        --config-file CONFIG_FILE   alternative xml config file. Default: /.../astroReport.config.xml
        --ekos                generate ekos sequences. Default: False
        --wait-on-exit, --woe   wait on exit. Default: False

Opciones:

dirs: directorio(s) a analizar
- -v: imprime información de depuración
- -V: imprime versión y termina
- -h: imprime la ayuda
- --config-file: archivo de configuración general. Defecto: astroReport.config.xml
- --ekos: genera la secuencias necesarias para importar en kstars/ekos. Default: False  
- --wait-on-exit, --woe: espera a pulsar una tecla al finalizar. Default: False  

Ejemplo básico:  

    ./astroReport /astro/proyectos/M_42

ARCHIVO DE CONFIGURACIÓN GENERAL
==============
En el mismo directoro donde esté astroReport debe de estar su archivo de configuración general: astroReport.config.xml  

- general: sección general de configuración
    - fitfile  
        - extensions: extensiones de archivos que astroReport analizará. Normalmente éstas seran .fit y .fits
        - filters
            - naturalOrder: orden en el que quieres que aparezcan tus filtros en el informe

- astrobin: esta sección (opcional, la puedes comentar y no se usará) es para los usuarios de astrobin. Si quieres que astroReport genere también el csv para pegar las sesiones al subir las fotos a astrobin, primero tienes que averiguar qué identificador le asocia astrobin a cada uno de tus filtros. No es trivial pero tampoco complicado:  
    - Ve a los settings de tu cuenta de usuario.
    - Después a 'Equipment' y pincha sobre uno de tus filtros. En la URL a donde te ha llevado, después de "/filter" hay un número. Ese es el ID de tu filtro.
    - Apúntalo y repite con cada uno de ellos. Una vez los tengas:
        - filtersID: por cada uno de tus filtros, define el ID correspondiente, tal y como viene de ejemplo
        - equipment: en esta etiqueta se define varios parámetros de tu equipo: razón focal, número de darks que usas para tu calibración, flats y bias

- ekos: sólo para los usuarios de kstars/ekos que quieren generar las secuencias correspondientes según los lights que queden por tomar
    - location: localidad de observación. Actualmente no se usa este valor, pero está pensado para un futuro
    - templates: no es necesario modificarlo. Se indican en qué subdirectorio están las plantillas de ekos para generar las secuencias. Puedes modificarlas según tu necesidad
    - sequences
        - dir: directorio donde generará las secuencias para importarlas en ekos
    

ARCHIVO DE CONFIGURACIÓN DE PROYECTOS
==============
astroReportProjectInfo.xml.example: renombra a astroReportProjectInfo.xml y cópialo al directorio que quieres analizar.  
Este archivo de configuración definirá tu proyecto en cuanto a número de lights necesarios, filtros, etc.  

- objects: lista de tags 'object' con los objetos que componen tu proyecto
    - object
        - name: nombre principal del objeto según aparece en la cabecera OBJECT del fit
        - aliases: es posible que algún fit tenga un nombre (cabecera OBJECT) ligeramente diferente pero que sin embargo pertenezca al mismo proyecto. En tal caso defínelo aquí con una lista de alias separados por coma
        - exposures: definiremos aquí las características de los lights que queremos hacer
            - filter
                - name: nombre del filtro 
                - subexposures: duración de la exposición del light con dicho filtro
                - requiredTotalExposure: exposición total (en segundos) que queremos hacer con el filtro
                - gain: ganancia que usaremos
                - offset: y el correspondiente offset
                - binning: binning que usaremos
        - referenceFit: sólo para usuarios de ekos. Al generar las secuencias para el secuenciador, usará el fit indicado
            - file: path completo al fit de referencia. Si se indica "auto", astroReport buscará en 'sequences -> dir' (ver archivo de configuración general) todos los fits y usará de referencia el primero que encuentre que coincida el nombre del objeto (cabecera OBJECT) con el objeto de nuestro proyecto
        - camera: características de disparo de la cámara (solo ekos)
            - temperature: temperatura de disparo de la cámara
            - width y height: ancho y alto del frame a capturar. Normalmente, deberás poner aquí el tamaño del sensor, en
        - filename
            - regexes: sólo analiza los fits que coinciden con las expresiones regulares indicadas (separadas por ,). La macro %%OBJECT%% será sustituida por cada uno de los nombres y alias de los objetos del proyecto. Esta sería su forma más común de uso: "^.\*%%OBJECT%%.*"  tal y como viene en el xml de ejemplo

