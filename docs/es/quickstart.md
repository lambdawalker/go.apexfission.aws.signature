# Compilar e integrar

Solo Desarrollo: no hay una versión confirmada del módulo, una versión instalable ni una URL pública confirmada. Clone la rama coordinada y revise la [política de seguridad](security.md) antes de operar un verificador. El módulo declara Go 1.26.0; use esa cadena de herramientas. Python 3.11+ genera la documentación sin dependencias externas. Los requisitos de Pulumi y despliegue corresponden a operaciones, no a la instalación de consumidores.

```bash
git clone --branch feat/sworn-ink-signatures https://github.com/lambdawalker/go.apexfission.aws.signature.git
cd go.apexfission.aws.signature
go test -race ./...
go vet ./...
GOOS=linux GOARCH=arm64 go build -o build/bootstrap ./cmd/api
python3 sites/build.py --check
```

Estos pasos validan y compilan localmente; no crean recursos AWS. Consulte los resultados de CI de esta revisión: el manual no demuestra que un dispositivo o despliegue AWS haya superado pruebas. Para consultar el sitio generado, ejecute `python3 -m http.server 8000 --directory sites/dist` y abra `http://localhost:8000`.

## Secuencia de integración

- Obtenga un token de acceso del emisor de confianza existente. La identidad es el par exacto emisor y sujeto del JWT. Ese emisor gestiona el correo verificado y la emisión de tokens.
- Descubra las capacidades Android y solicite un desafío `register` con las suites admitidas. Use únicamente la suite elegida por el servidor, sin degradación automática si falla la creación de la clave.
- Genere una clave Android atestada usando el nonce decodificado como desafío de atestación. Calcule `keyId` sobre el DER SubjectPublicKeyInfo de la hoja y construya la declaración de registro.
- Autorice la firma de la declaración con BiometricPrompt y envíe la cadena, hoja primero, y la firma DER a `/v1/registrations`.
- Calcule el hash de los bytes exactos del documento. Solicite un desafío `sign` con `keyId`, el resumen y las suites; autorice la declaración recibida con BiometricPrompt y envíe el documento original y la firma a `/v1/signatures`.
- Considere terminada la operación solo después de guardar las pruebas y completar la actualización condicional. Conserve `evidenceId` y `keyId`.

La [API HTTP](api.md) muestra las solicitudes y el [protocolo](protocol.md) define los bytes. La [integración Android](https://github.com/lambdawalker/android.apexfission.signature/blob/feat/sworn-ink-signatures/docs/agents/installation.md) mantiene las API cliente; no traslade declaraciones Go a Kotlin.
