# Fallos y recuperación

## Autenticación o política rechazada

Ante `401`, compruebe que la solicitud atravesó el autorizador JWT configurado con emisor HTTPS correcto y sujeto presente. Ante `403`, compruebe el ámbito del token. No omita autorización para depurar. Ante `400`, compare bytes de la declaración con el [Protocolo](protocol.md): base64 frente a base64url, DER frente a JOSE, huella SPKI y resumen exacto del documento. Paquete/certificado de aplicación, hardware, biometría, arranque, raíces y disponibilidad de revocaciones pueden rechazar una firma matemáticamente válida.

Cancelación biométrica, bloqueo, ausencia de biometría o clave Android invalidada no equivalen a éxito servidor. Siga el ciclo de errores Android. Si cambia la inscripción biométrica y se invalida la clave, obtenga desafío y clave nuevos; no sustituya por software.

## Caducidad y conflicto

Si caduca un desafío pendiente, obtenga otro y una firma biométrica nueva: cambiar el desafío cambia los bytes. `409` también puede indicar otra solicitud que ya lo reclamó. No sustituya bytes ni reinicie estado por fuerza. Cambiar de cuenta requiere claves y desafíos del nuevo par emisor/sujeto. Un `404` no debe revelar claves ajenas ni demostrar ausencia de pruebas.

## Persistencia interrumpida

Un fallo de almacenamiento/KMS/TSA o de respuesta HTTP puede ocurrir después de reclamar el desafío. Repita la misma operación con valores decodificados idénticos, firma original y documento/cadena originales; el espacio u orden JSON puede variar. El hash se calcula serializando la solicitud tipada; una firma DER nueva es otra solicitud. Proteja el material de recuperación hasta completar. Limite reintentos y use espera incremental; renueve la autenticación externa con el emisor cuando corresponda.

El servicio busca `evidence/<challengeId>.json` y solo lo crea si no existe. Puede reutilizar un sobre coincidente y reintentar la finalización DynamoDB. Registrar la clave y completar el desafío sucede mediante condiciones en una transacción. La caducidad pendiente se comprueba antes de reclamar; una solicitud idéntica ya reclamada puede terminar tras el plazo mientras se conserve su estado. La limpieza usa `ttlAt` siete días después de caducar el desafío, separado del plazo de autorización de cinco minutos. Tras la limpieza TTL de AWS no se garantiza el reintento; las pruebas S3 persisten. Reintente pronto. No hay atomicidad entre DynamoDB y S3. Un objeto o estado en proceso por sí solo no demuestra firma completa.

Si continúa el fallo, un operador autorizado debe revisar estado, hash, objeto/versiones y logs sin exponer datos o credenciales. Conserve artefactos; no sobrescriba pruebas, borre bloqueos ni fabrique la finalización. No hay API de estado/recuperación de consumidores aparte de repetir estos POST, ni recuperación automática de cuenta o clave.

## Revocación y disponibilidad

La consulta Google usa HTTPS fijo, rechaza redirecciones, limita el tiempo a diez segundos y conserva datos hasta cinco minutos. Fallos de red, datos mal formados/obsoletos o números revocados/suspendidos bloquean la verificación. Restaure el servicio y reintente sin deshabilitar revocaciones. Un fallo del proveedor de tiempo configurado también impide completar; no tener proveedor significa `unavailable` explícito.

## Recuperar configuración de despliegue

Si no puede descargarse el YAML autoritativo, deténgase y restaure el objeto cifrado correcto y los metadatos del proveedor de secretos en el prefijo de estado existente. La herramienta conserva el YAML local si falla la descarga, pero su presencia no autoriza continuar. No borre un archivo local para superar los controles iniciales ni regenere la contraseña Pulumi, claves de prueba/firma o almacén cifrado. La respuesta remota explícita de objeto ausente permite setup inicial solo sin YAML local y con `setup --approve`; una pila existente sigue necesitando su configuración autoritativa. Restaure el almacén en su ámbito original de proyecto/entorno y conserve las claves de desbloqueo originales.

Ante un destino discordante, revise juntos `aws:region`, `awsAccount` y la lista unitaria `aws:allowedAccountIds` restaurados, además de cuenta, región, entorno, backend de estado y rol STS seleccionados. Use reconfiguración explícita con entradas completas revisadas; no edite una copia local para eludir la restricción del proveedor. Cambiar cuenta/región no migra infraestructura. Ante denegaciones de límite/confianza/etiquetas, revise `oidc-plan` y recurra al operador bootstrap privilegiado separado. No permita al rol de despliegue modificar su límite de runtime ni retire condiciones de etiquetas API para superar una denegación.
