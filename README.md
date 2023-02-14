PerformanceF5

PerformanceF5 es un script creado en python para generar reportes de salud de dispositivos big ip.
Este script no tiene nada en común con iHealh.f5.com.
Lo que hace el script es abrir una conexión ssh/sftp al dispositivo big ip, extraer informacion usando comandos de shell/tmsh y generar un reporte en formato html compatible con MS Word para su posterior edición 
En el directorio dist existen versiones compiladas con pyinstaller (ejecutables)  para windows y linux.

Creado por Juan Salinas para KData.cl. 2023.

Contacto: https://www.linkedin.com/in/juansalinasc/

Casos de uso:

1.-Generar reportes usando listado de dispositivos y credenciales en archivo csv.

    performanceF5.exe -d ruta_directorio_destino_del_reporte -n nombre_del_informe -f example.csv

NOTA: Revisar example.csv para ver el formato. 
Las contraseñas en texto plano serán cifradas por PerformanceF5 usando la contraseña de cifrado provista por el usuario.

2.-Generar reportes especificando  usuario y listado de dispositivos.

    performanceF5.exe -d ruta_directorio_destino_del_reporte -n nombre_del_informe -u miusuario -l mihost.midominio.cl,192.168.0.1

NOTA: El script solicitara la contraseña para el nombre de usuario especificado.
