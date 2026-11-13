# Recetas de integración

## Reproducir el vector compartido

Use los nueve campos de `protocol/test-vectors/v1.json`. Codifique longitudes UTF-8 y compare cada byte con `encodedHex`. La prueba incluye texto no ASCII, resumen vacío y texto base64 para detectar errores al contar caracteres. Ejecute pruebas Go y de codificación Android sobre el mismo vector. No envíe su desafío de ejemplo como solicitud real.

```bash
go test ./protocol ./attestation ./service ./api
```

## Registrar y después firmar

Siga [Inicio rápido](quickstart.md) usando los [cuerpos HTTP](api.md). Genere la clave después de recibir el nonce. Conserve la cadena y obtenga el identificador del SPKI de la hoja. Pida autorización biométrica nueva para cada declaración completa. Calcule el hash de los bytes que enviará, no de una vista previa ni de una cadena normalizada. Conserve declaración, firma y solicitud si hay que recuperar un fallo de red. No registre tokens de acceso en logs.

## Verificar las pruebas conservadas

Obtenga el sobre por una ruta de almacenamiento autorizada por el operador; no existe API de descarga para consumidores. Conserve los bytes originales de la carga: KMS firma su SHA-256, no una interpretación serializada de nuevo. Verifique el sello DER ECDSA con la clave pública de recibos y el algoritmo de confianza. Distribuya la clave esperada por un canal fiable; incluirla en el sobre no demuestra su confianza. Reconstruya los campos, compruebe resumen del documento, firma cliente, propietario y desafío, y aplique la política y las pruebas de raíces/revocación pertinentes a la decisión.

`verifiedAt` procede del reloj servidor; no prueba una hora independiente. Con un proveedor inyectado, valide token y vínculo del resumen de carga más sello con una política TSA de confianza separada. El runtime predeterminado carece de proveedor. Las herramientas de validación independiente y descarga pública son trabajo de integración pendiente; no se ofrece un verificador offline completo.

## Ampliar el sellado de tiempo

Implemente `service.TimestampProvider.Timestamp(context.Context, []byte) ([]byte, error)`. Recibe el resumen SHA-256 del JSON combinado de carga y sello. El proveedor DEBE validar confianza TSA, resumen, política, nonce y hora antes de devolver un token; devolver bytes arbitrarios incumple el contrato. Un fallo o token vacío impide completar la operación. No se incluye TSA simulada, cliente HTTP RFC3161 predeterminado ni afirmación de tiempo independiente.

## Revisar planes sin aplicar cambios

Use la [guía de herramientas de despliegue](https://github.com/lambdawalker/go.apexfission.aws.signature/blob/feat/sworn-ink-signatures/docs/deployment.md) para aportar entorno, perfil SSO, cuenta, región y prefijo privado de estado S3 existente. `--action oidc-plan` muestra confianza OIDC, política IAM de despliegue y límite de runtime sin crearlos; `--action preview` restaura configuración cifrada autoritativa, valida un único destino de cuenta, compila y guarda un plan Pulumi actualizado sin aplicarlo. Preview requiere acceso a configuración y estado correctos. Bootstrap IAM es un paso separado con aprobación explícita; un plan correcto no demuestra despliegue real ni autoriza aplicarlo.
