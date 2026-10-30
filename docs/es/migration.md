# Versiones y migración

Solo hay documentación de Desarrollo. No se registran versiones confirmadas ni manuales históricos; el archivo inicial está vacío. Una etiqueta Git no demuestra publicación correcta. `sworn-ink/v1` identifica el contrato de red, no una versión publicada del módulo Go. No deduzca una dependencia `v1.0.0`.

Los cambios coordinados de Desarrollo deben actualizar juntos el [Protocolo](protocol.md), el vector Go/Android y las pruebas negativas. Revise orden de campos, longitudes en bytes, nonce, suites, DER, propietario, JSON y política de pruebas antes de modificar un cliente. Los cambios incompatibles necesitan estrategia explícita de versión; no hay negociación automática de otro protocolo.

## Archivo futuro de versiones

`catalog.json` expone una lista vacía de versiones y rutas de Desarrollo localizadas. Antes de anunciar una versión, registre módulo/versión/destino de publicación confirmados, coordenadas exactas, commit/etiqueta inmutables, identidad inmutable de documentación y procedencia de traducción. Conserve todos los registros y añada correcciones separadas del código. Genere cada versión desde su contenido registrado y falle si falta. El generador actual rechaza un catálogo no vacío hasta implementar instantáneas históricas; no debe etiquetar páginas actuales como antiguas.

Los enlaces permanecen en idioma y alcance de Desarrollo elegidos. El cambio de idioma conserva la guía. El Markdown original tiene el mismo alcance. No se muestra un selector de versiones ficticio. `IMPORT.md` solo indica instalación desde código hasta verificar publicación.

## Autoría de documentación

Edite primero `docs/agents/*.md`, revise el español correspondiente en `docs/es/*.md`, conserve bloques ejecutables y después actualice solo los SHA-256 revisados en `docs/es/manifest.json`. Una traducción ausente/obsoleta bloquea el build. El manifiesto generado calcula hashes de código y documentos en cada build; generarlo no demuestra revisión humana de cambios.

```bash
python3 -m unittest discover -s sites -p 'test_*.py'
python3 sites/build.py --check
```

El generador borra resultados obsoletos y valida enlaces internos. Cuando haya navegador, revise anchuras móvil/escritorio, teclado y movimiento reducido. Las pruebas HTML no acreditan revisión visual. El despliegue GitHub Pages usa otro flujo manual de main, sin publicar paquetes ni recursos AWS.
