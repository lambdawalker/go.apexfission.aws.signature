# Sworn Ink — Desarrollo

Este servicio Go verifica firmas biométricas de Android con protección por hardware y conserva pruebas selladas en AWS. Este manual describe el código de `feat/sworn-ink-signatures`; no se confirma una versión publicada ni un servicio desplegado. El inglés es la fuente canónica y todas estas guías tienen traducción al español. El repositorio Go mantiene el protocolo compartido.

## Comience aquí

- [Inicio rápido](quickstart.md): compilar y seguir el registro y la firma.
- [Conceptos](concepts.md): identidad, propiedad de claves, desafíos y pruebas.
- [Protocolo](protocol.md): bytes exactos para interoperar.
- [API HTTP](api.md): solicitudes y respuestas autenticadas.
- [Recetas](recipes.md): integración y verificación independiente.
- [Seguridad y límites](security.md): política de confianza y límites sin verificar.
- [Solución de problemas](troubleshooting.md): recuperación segura.
- [Migración](migration.md): compatibilidad de Desarrollo y futuras versiones.
- [Operación en AWS](operations.md): inventario y límites operativos.

## Biblioteca complementaria y código

La [documentación Android de Desarrollo](https://github.com/lambdawalker/android.apexfission.signature/blob/feat/sworn-ink-signatures/docs/agents/index.md) explica la interfaz biométrica y el ciclo de vida de las claves. Las ramas están coordinadas; los enlaces pasarán a revisiones conservadas de main al integrarse. El [código Go](https://github.com/lambdawalker/go.apexfission.aws.signature/tree/feat/sworn-ink-signatures) contiene pruebas ejecutables del protocolo, la atestación y el servicio. El HTML y el Markdown descargable proceden de estas mismas guías. El manifiesto SHA-256 identifica los bytes exactos del código revisado; acredita su correspondencia, no una firma ni una publicación.
