# Inventario AWS y contrato operativo

El código describe un diseño desplegable; no se confirma infraestructura real ni aceptación. Consulte [herramientas de despliegue](https://github.com/lambdawalker/go.apexfission.aws.signature/blob/feat/sworn-ink-signatures/docs/deployment.md) para comandos, persistencia de ajustes, recuperación del almacén cifrado y confirmaciones. Compilar, previsualizar o consultar estado no autoriza desplegar. Seleccione explícitamente cuenta, región, entorno, estado S3 y credenciales.

## Propiedad de recursos

- API Gateway HTTP API: tres rutas POST, emisor/audiencia JWT y ámbito obligatorio, integración proxy Lambda y limitación de tráfico.
- Lambda: ARM64 `provided.al2023` con `bootstrap` compilado, memoria/tiempo explícitos y rol limitado a dependencias y logs.
- DynamoDB: tabla bajo demanda con `pk`, estado condicional de claves/desafíos, limpieza TTL, recuperación puntual y cifrado KMS.
- S3 de pruebas: privado, versionado, acceso público bloqueado, política TLS, SSE-KMS predeterminado y objetos deterministas de creación única. Borrado forzado deshabilitado. Versionar no equivale a bloqueo de cumplimiento.
- KMS de almacenamiento: cifra pruebas y estado con rotación. KMS de recibos: clave asimétrica P-256 independiente para firma, no para cifrado.
- IAM/CloudWatch: permisos acotados a tabla/objetos/KMS y conservación de logs. Las raíces revisadas pueden estar en un objeto S3 protegido con permiso de lectura. No se crean Cognito, servicio de correo ni TSA integrada.

## Configuración del runtime

Son obligatorios `DOCUMENT_BUCKET`, `STATE_TABLE`, `RECEIPT_KEY_ID`, `JWT_ISSUER`, `ALLOWED_APP_PACKAGE` y `ALLOWED_APP_DIGESTS`. Los resúmenes de certificados firmantes de aplicación son hex SHA-256 separados por comas. `JWT_SCOPE` vale `signature:write` por defecto y debe coincidir con Gateway. La audiencia JWT se exige en Gateway, no se elige en JSON cliente.

Aporte raíces revisadas mediante `GOOGLE_ROOTS_PEM`, o use juntos `GOOGLE_ROOTS_BUCKET`, `GOOGLE_ROOTS_KEY` y `GOOGLE_ROOTS_SHA256` si falta PEM. Los bytes del objeto deben coincidir con SHA-256 fijado. El conjunto admite hasta 64 KiB de certificados CA válidos. Ruta y hash son ajustes del operador; las solicitudes no aportan raíces de confianza. `AWS_REGION` y credenciales usan la cadena SDK; el despliegue local usa SSO y CI usa OIDC acotado, sin claves en Git.

## Operación y conservación

Supervise errores/tiempos Lambda, limitación de tráfico, conflictos, fallos S3/KMS y conectividad de revocaciones Google. Alarmas y umbrales requieren ajustes del operador. No registre documentos ni tokens. Elija conservación y pruebe restauración autorizada de versiones S3 y backups puntuales DynamoDB; necesita claves KMS y permisos vigentes. No elimine ni rote claves de recibos sin conservar cómo verificar los existentes.

Antes de aceptar producción, pruebe denegaciones de token/ámbito, cuentas cruzadas, registro real y cancelación/cambio biométrico, atestación revocada/obsoleta, reintento idéntico tras cada escritura, reconstrucción y verificación KMS. Observe privacidad, aislamiento regional/de cuenta, recuperación y conservación en el entorno elegido. Las pruebas unitarias locales no acreditan esas comprobaciones de nube/dispositivo.

## Identidad de despliegue y límites de permisos

Antes de seleccionar u operar una pila Pulumi, la herramienta descarga el YAML cifrado autoritativo y los metadatos del proveedor de secretos desde `DEPLOY_BACKEND/ENV/config/Pulumi.ENV.yaml`, incluso si existe YAML local. Descarga a un archivo temporal y sustituye la configuración local solo tras restaurar correctamente contenido no vacío. Si falla, conserva el archivo local y se detiene; no permite usarlo como alternativa ni regenerar secretos. La configuración inicial requiere respuesta explícita de objeto ausente, ningún YAML local y `--action setup --approve`; una pila existente sin su configuración cifrada remota exige recuperación.

Antes de preview/status/recovery, comprueba `aws:region`, `awsAccount` del proyecto y `aws:allowedAccountIds` del proveedor contra el destino seleccionado. La lista debe contener exactamente esa cuenta. Setup/reconfigure escribe esa restricción y valida la configuración. Justo antes de aplicar el plan guardado, vuelve a comprobar cuenta/rol STS y destino del proveedor. Una sesión AWS válida por sí sola no demuestra que Pulumi use región o destino correctos.

Una identidad de bootstrap con privilegios separados revisa `--action oidc-plan` y, solo con autorización explícita, ejecuta `--action oidc-setup --approve`. La confianza se limita al emisor GitHub Actions, `aud=sts.amazonaws.com` y sujeto exacto `repo:OWNER/REPO:environment:ENV`. Bootstrap crea o verifica el límite fijo `arn:aws:iam::ACCOUNT:policy/sworn-ink-ENV-runtime-boundary`; el rol Lambda de Pulumi siempre lo referencia. El rol normal de despliegue solo puede crear ese rol de runtime con el límite y no puede retirarlo, sustituirlo ni modificar versiones de su política. Un permiso inline más amplio sigue limitado por esa política de bootstrap a tabla, objetos de pruebas/raíces, claves KMS etiquetadas y logs del entorno.

Crear una API requiere etiquetas de solicitud de proyecto/entorno; administrarla después exige etiquetas de recurso coincidentes. Si AWS no evalúa esas condiciones en una operación descendiente, el despliegue se bloquea en lugar de ampliar acceso a todas las API regionales. Crear concesiones KMS para DynamoDB se limita a claves etiquetadas del entorno y `kms:GrantIsForAWSResource=true`. Son restricciones revisadas del código, no evidencia de aceptación IAM real; valide el proveedor en una cuenta aislada antes de producción y separe privilegios de bootstrap y credenciales de despliegue.

## Alojamiento del manual

El flujo manual GitHub Pages solo admite main de confianza. Genera con acceso de lectura y concede permisos Pages/OIDC únicamente al trabajo de publicación. No despliega AWS ni publica paquetes o versiones. Configure Pages y el entorno protegido `github-pages` antes de iniciarlo explícitamente. No se afirma una URL alojada hasta que el flujo termine correctamente.
