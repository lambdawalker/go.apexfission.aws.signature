# Política de seguridad y límites

## Entradas de confianza

Solo las raíces de atestación hardware de Google revisadas por el operador establecen confianza. La raíz enviada por el cliente y la PKI web del sistema no la amplían. Rote raíces deliberadamente con material revisado. Deben estar permitidos tanto el paquete como el SHA-256 del certificado firmante de la aplicación. Emisor, audiencia y ámbito JWT son ajustes del operador; las solicitudes no eligen raíces ni proveedores de identidad.

## Comprobaciones de atestación

El verificador comprueba ruta X.509 completa, validez y restricciones, clave P-256, vínculo del nonce, niveles hardware de atestación y keymaster, origen generado, propósito de firma, algoritmo/curva EC y SHA-256, autorización exclusivamente biométrica por operación, arranque verificado bloqueado e identidad de aplicación permitida. Rechaza etiquetas duplicadas o mal formadas e identidades de aplicación no fiables. Rechaza `noAuthRequired` y autorización temporal. Cada número de serie de la cadena verificada se contrasta con revocaciones recientes de Google; datos obsoletos o fallos de descarga bloquean la operación. Cada firma revalida la cadena registrada.

La invalidación al cambiar biometría se solicita localmente; el certificado no demuestra explícitamente ese ajuste. Su cumplimiento requiere pruebas Android reales. Informar de capacidades no sustituye la atestación. StrongBox y la experiencia biométrica varían según dispositivo y API; no confunda pruebas de emulador con protección hardware.

## Reutilización y persistencia

El desafío vincula propietario, operación, suite, clave, nonce y resumen del documento. Las reclamaciones condicionales impiden reutilizarlo con otros bytes. Las pruebas se escriben una sola vez en una ruta S3 determinista. El sello KMS debe completarse antes del éxito; S3 y DynamoDB no forman una única transacción. Un fallo puede dejar una operación en proceso que un reintento idéntico termina. Nunca convierta pruebas incompletas en éxito.

## Alcance

El servicio demuestra uso de una clave hardware aceptada por la política y los bytes firmados de la cuenta autenticada. No demuestra identidad legal, consentimiento informado, comprensión del documento ni validez jurídica. JWT/correo corresponden al proveedor externo. El sello KMS no aporta tiempo independiente y el runtime lo declara no disponible. Estos documentos no acreditan aceptación AWS real, verificación de hardware Android, auditoría externa ni preparación para producción.

El documento admite 512 KiB; el cuerpo HTTP JSON decodificado, 1 MiB. Las pruebas contienen documentos originales y material sensible de identidad/atestación. Restrinja S3, KMS y estado, revise conservación/borrado y evite registrar documentos o tokens. Un bucket privado cifrado con versiones no constituye retención inmutable de cumplimiento. No hay negociación de cifrado de aplicación, API de recuperación de cuentas, búsqueda pública de pruebas ni ruta de revocación de claves para usuarios.
