# APT Model Generator

## Tabla de contenido
* [Información general](#información-general)
* [Tecnologías](#tecnologías)
* [Instalación](#instalación)
* [Ejecución](#ejecución)

## Información General
El programa APTModelGenerator tiene como objetivo trabajar sobre la generación y simulación de modelos formales, parametrizables y aleatorios de APTs según el estándar MITRE. La creación de dicho progrmama tiene como finalidad formar parte de un proyecto de mayor escala conocido como COBRA orientado al desarrollo de  cibermaniobras adaptables y personalizables de simulación hiperrealista de APT y entrenamiento en ciberdefensa a través de la gamificación.

## Tecnologías
El proyecto se ha creado utilizando las siguientes tecnologías:
* Python versión ````3.7.9````
* STIX, del inglés Structured Threat Information Expression es un formato de lenguaje y serialización que se utiliza para intercambiar inteligencia sobre amenazas cibernéticas. Este proyecto emplea STIX versión ````2.1````. Para más información, acceda a la [documentación](https://oasis-open.github.io/cti-documentation/stix/intro) oficial de STIX.
* MITRE ATT&CK® es una fuente de infoemación, accesible a nivel mundial, de tácticas y técnicas adversas basadas en observaciones del mundo real. [Pagina oficial](https://attack.mitre.org/) de MITRE.

## Instalación
Para el arranque del proyecto deberá:
* Instalar librería sqlite3.
```$ pip install sqlite3```
* Instalar librería python-stix2.
```$ pip install stix2```
**Nota:** La librería require una versión de Python 3.6+. Para obtener documentación más detallada, consulte el repositorio [cti-python-stix2](https://github.com/oasis-open/cti-python-stix2) gestionado por el Comité Técnico de Inteligencia de Ciberamenazas de OASIS.
* Clonar el repositorio [ATTACK-Tools](https://github.com/nshalabi/ATTACK-Tools.git).

## Ejecución
Previo a la ejecución, será necesario modificar la dirección en la que se almacena la base de datos dentro en el equipo local. Deberá introducir en ```APTModelGenerator``` la ruta completa del fichero ```attack_view_db.sqlite```.

Una vez instaldo el programa y realizados los cambios anterioriormente descritos, se podrá ejecutar desde el terminal con el siguiente comando.

```$ python APTModelGenerator.py```.

Paso seguido, el programa solicitará introducir el número de patrones de ataque que se desean extraer en la consulta a la base de datos de ATTA&CK. El resultado de esta ejecución es un fichero de nombre ```APTModelGenerated.json``` con el modelo APT generado. 

Para la representación gráfica de los distintos componentes que constituyen el modelo, el fichero generado deberá introducirse en el [visualizador STIX](https://oasis-open.github.io/cti-stix-visualization/n).
