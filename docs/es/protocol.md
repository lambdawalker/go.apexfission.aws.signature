# Protocolo v1 — contrato autoritativo

El repositorio Go mantiene este contrato. Android y Go deben producir bytes idénticos. Los campos binarios usan base64 estándar con relleno, nunca base64url. Resúmenes e identificadores son 64 caracteres hexadecimales SHA-256 en minúsculas. Las cadenas contienen certificados DER, hoja primero. Las firmas ECDSA usan ASN.1 DER, nunca JOSE `r || s`.

## Declaración firmada exacta

Concatene estos nueve campos UTF-8 en este orden exacto. Ante CADA campo escriba su longitud en bytes como entero sin signo de 32 bits big-endian. Una cadena vacía conserva un prefijo de cuatro bytes cero. La longitud cuenta bytes UTF-8, no caracteres. No añada separadores, salto final, normalización Unicode ni serialización JSON.

- `sworn-ink/v1`
- operación: `register` o `sign`
- suite elegida: `ES256_STRONGBOX` o `ES256_TEE`
- `challengeId`
- nonce como TEXTO base64 estándar con relleno, no como bytes decodificados
- emisor JWT de confianza
- sujeto JWT de confianza
- `keyId`: SHA-256 del DER SubjectPublicKeyInfo del certificado hoja
- `documentSHA256`: vacío al registrar; resumen de los bytes exactos del documento al firmar

`protocol.Statement.Encode()` implementa la codificación. El primer campo tiene doce bytes: el inicio hexadecimal es `0000000c73776f726e2d696e6b2f7631`. `protocol/protocol_test.go` conserva el vector compartido; el codificador Android debe coincidir. El protocolo no depende del orden de miembros JSON.

Firme la declaración completa mediante `SHA256withECDSA` de Android. El verificador calcula SHA-256 una sola vez y verifica la firma DER con P-256. No calcule previamente el hash de la declaración antes de pasarla a `SHA256withECDSA`. El verificador Go de bajo nivel `VerifyDocumentHash` recibe directamente un resumen SHA-256 de 32 bytes, sin calcular otro hash. En producción, `VerifySignature` calcula una vez el hash de la declaración completa y delega en ese verificador. No hay operación HTTP para firmar un resumen de documento en bruto.

## Registro

Solicite el desafío antes de generar la clave. Decodifique el nonce y use esos bytes como desafío de atestación Android. Obtenga `keyId` del SPKI de la hoja y codifique la declaración con el mismo emisor/sujeto de confianza del token de acceso. El servidor reconstruye esta declaración; la solicitud de registro no la aporta. Para firmar, la declaración devuelta es el base64 de los bytes codificados, que se decodifican y autorizan.

## Acuerdo y duración

El nonce tiene 32 bytes aleatorios criptográficos. El desafío caduca tras 300 segundos. El registro elige el hardware preferido por el servidor; la firma conserva la suite registrada. Un fallo no permite degradación automática. El documento admite hasta 524288 bytes decodificados. TLS protege el transporte y SSE-KMS las pruebas guardadas; aquí no se negocia cifrado de aplicación.

La [API HTTP](api.md) define mensajes y [Seguridad](security.md) define la confianza. La [implementación Android](https://github.com/lambdawalker/android.apexfission.signature/tree/feat/sworn-ink-signatures) debe cumplir este contrato.
