# Identidad y ciclo de vida

## Propiedad

El autorizador JWT de confianza aporta `issuer` y `subject`; su par exacto es propietario de claves y desafíos. El correo no identifica la cuenta. Ningún cuerpo de registro o firma elige el emisor. API Gateway valida emisor, audiencia y ámbitos; Lambda rechaza eventos sin declaraciones del autorizador. Las pruebas directas inyectan identidades sin crear un modo de red sin autenticación.

## Política de hardware

Ambas suites usan ECDSA P-256 y SHA-256. En el registro, `ES256_STRONGBOX` tiene preferencia sobre `ES256_TEE`, independientemente del orden cliente. El desafío de firma conserva la suite de la clave registrada, que debe estar entre las ofrecidas. Las capacidades son orientativas: la atestación demuestra el nivel real. Un fallo tras la selección requiere una nueva operación explícita; no se permite pasar a software.

## Estado del desafío

El desafío tiene un nonce aleatorio de 32 bytes y cinco minutos de validez. El registro vincula una clave con su propietario; la firma vincula una clave registrada con el resumen exacto del documento. La caducidad se exige mediante condiciones; el TTL de DynamoDB limpia de forma asíncrona y no autoriza solicitudes. Una reclamación condicional vincula el desafío al hash de la solicitud antes de escribir las pruebas. Los reintentos en proceso o completos deben coincidir con ese hash. Otros bytes causan conflicto.

## Pruebas

El sobre JSON contiene la carga de pruebas, el sello KMS y el estado de tiempo. La carga incluye declaración exacta, firma, documento firmado, clave y cadena de registro, identidad del desafío, hora de verificación y política. KMS firma SHA-256 de la carga. La clave de firma y la de cifrado tienen funciones distintas. Sin proveedor independiente, `timestamp.status` es `unavailable`; el reloj servidor o recibo KMS no constituye un sello de tiempo independiente.

El servicio no posee goroutines de fondo. Configure las dependencias antes de servir; almacenes, firmantes, verificadores y proveedores de tiempo deben admitir concurrencia. Los contextos propagan cancelaciones. Desconectar el cliente no revierte una operación reclamada o persistida: use el mismo reintento descrito en [recuperación](troubleshooting.md).
