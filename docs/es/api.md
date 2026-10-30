# API HTTP autenticada

Las tres rutas aceptan `POST` JSON y requieren `Authorization: Bearer <access-token>`. Use una URL HTTPS proporcionada por el operador. Son obligatorios emisor/audiencia/ámbitos de Gateway y las declaraciones del autorizador de Lambda. `issuer` y `subject` de la respuesta de desafío son autoritativos para construir la declaración de registro. No hay ruta para correo, creación de usuarios, emisión de tokens ni descarga pública de pruebas.

## POST /v1/challenges

Solicitud de registro:

```json
{"operation":"register","suites":["ES256_STRONGBOX","ES256_TEE"]}
```

Solicitud de firma (sustituya los marcadores por resúmenes de 64 caracteres hexadecimales en minúsculas):

```json
{"operation":"sign","suites":["ES256_STRONGBOX","ES256_TEE"],"keyId":"<leaf-SPKI-SHA256>","documentSHA256":"<document-SHA256>"}
```

La respuesta contiene `challengeId`, `nonce` (base64, 32 bytes decodificados), `suite`, `expiresAt` (segundos Unix), `issuer` y `subject`. Para firma incluye además `statement` (declaración completa en base64). El registro debe omitir `keyId` y `documentSHA256`. La firma requiere ambos y una clave de la cuenta autenticada. Se aceptan hasta 16 suites; los valores desconocidos no habilitan criptografía por software.

## POST /v1/registrations

```json
{"challengeId":"<challengeId>","certificateChain":["<base64-leaf-DER>","<base64-intermediate-DER>"],"signature":"<base64-ASN1-DER-signature>"}
```

Envíe la cadena de atestación con la hoja primero. El servidor valida contra las raíces configuradas, obtiene el identificador SPKI, reconstruye la declaración y verifica la firma. El nonce usado al generar la clave debe coincidir. El éxito devuelve `evidenceId`, `keyId` y `timestampStatus`.

## POST /v1/signatures

```json
{"challengeId":"<challengeId>","document":"<base64-original-document>","signature":"<base64-ASN1-DER-signature>"}
```

El documento decodificado admite hasta 512 KiB. El servidor calcula el hash, carga la clave de la cuenta, revalida su atestación original con revocaciones recientes, reconstruye la declaración y verifica la firma. El éxito devuelve `evidenceId`, `keyId` y `timestampStatus`. El runtime no instala proveedor de tiempo independiente: `timestampStatus` es `unavailable`.

## Resultados HTTP

Las rutas correctas devuelven JSON `200` tras completar la operación. Los errores contienen una cadena `error`. Las respuestas incluyen `Cache-Control: no-store` y `X-Content-Type-Options: nosniff`.

- `400 invalid_json`: JSON mal formado, campos desconocidos o duplicados, tipos incorrectos o datos posteriores.
- `400 verification_rejected`: solicitud inválida, documento distinto o atestación/firma rechazada.
- `401 unauthorized`: identidad de confianza ausente o incoherente.
- `403 insufficient_scope`: falta el ámbito requerido.
- `404 not_found`: ruta, desafío o clave propia no disponible.
- `409 expired_or_conflicting_operation`: desafío pendiente caducado, estado incompatible o solicitud diferente.
- `413 request_too_large`: cuerpo HTTP decodificado mayor de 1 MiB, límite distinto del documento.
- `503 unavailable`: dependencia del servicio sin configurar.
- `503 temporarily_unavailable_retry_same_request`: fallo de dependencia/almacenamiento; conserve los mismos valores decodificados para recuperarse.

Trate cada fallo explícitamente; la ausencia de pruebas no indica éxito. Los binarios JSON usan base64 estándar y los resúmenes hexadecimales en minúsculas; consulte el [Protocolo](protocol.md). Tras un fallo de transporte posterior a una escritura, el resultado es incierto: [Solución de problemas](troubleshooting.md) explica los reintentos idénticos. Los ejemplos son marcadores, no credenciales válidas de prueba.

## API Go para integración

- `service.Service.CreateChallenge(ctx, Identity, ChallengeRequest)` devuelve `Challenge`; `Register(ctx, Identity, RegisterRequest)` y `Sign(ctx, Identity, SignRequest)` devuelven `Response`. `Identity.Valid()` limita emisor/sujeto e `ID()` deriva la identidad de almacenamiento. `Challenge.StatementFor(keyID)` proporciona la declaración compartida.
- Configure `Service.Store`, `Attester` y `Signer` antes de servir; `TSA` es opcional y `Now` permite inyectar reloj. Las dependencias de producción obligatorias no deben ser nil. Comparta el servicio solo con dependencias seguras ante concurrencia; no posee trabajadores ni método `Close`.
- `service.Store` aporta `PutChallenge`, `GetChallenge`, `GetKey`, `Claim`, `Complete`, `GetEvidence` y `PutEvidence`. Un adaptador propio debe conservar condiciones de estado/propietario, creación única y finalización atómica del registro. `Complete` recibe una clave nueva opcional; nil completa una firma. Los almacenes de prueba en memoria no son adaptadores duraderos.
- `service.Attester.Verify` devuelve `attestation.Result` validado; `Signer.Sign` recibe un resumen SHA-256 de recibo de 32 bytes y devuelve `Seal`. `TimestampProvider` exige validar confianza según [Recetas](recipes.md). `Evidence`, `Envelope`, `Seal`, `Timestamp`, `Key` y `Challenge` definen los JSON conservados en `service/types.go`.
- `attestation.Verifier{Policy: ...}.Verify(ctx, chainDER, nonce, suite)` devuelve clave pública, identificador, nivel de seguridad, versión de atestación y paquete. `Policy` exige `Roots` revisadas, `AppPackage`, `AppSignerDigests` y `Revocations` que bloquee ante fallos; `Now` inyecta reloj. `NewGoogleRevocations(*http.Client)` construye el verificador de URL fija; nil usa su política HTTP predeterminada.
- `awsstore.NewStore(DynamoDBAPI, S3API, table, bucket)` implementa persistencia; `NewKMSSigner(KMSAPI, keyID)` firma recibos y verifica clave resuelta/firma. Los clientes siguen AWS SDK v2 y cancelación por contexto. El sobre de pruebas admite 2 MiB, distinto de los límites documento/HTTP.
- `api.Handler{Service, Issuer, Scope}.Handle(ctx, events.APIGatewayV2HTTPRequest)` devuelve la respuesta Gateway. Acepte solo eventos Gateway de confianza; las cabeceras no sustituyen al autorizador. Configure emisor/ámbito de forma coherente con Gateway.
- `protocol.SelectSuite`, `Statement.Encode`, `VerifySignature`, `VerifyDocumentHash`, `ValidHash` y `Hash` son utilidades descritas en [Protocolo](protocol.md). `StrongBox`, `TEE` y `MaxDocumentBytes` exponen constantes de política.

Los errores centinela son `ErrInvalid`, `ErrNotFound` y `ErrConflict`; use `errors.Is` porque pueden envolverse. Otros fallos de dependencias se presentan como indisponibilidad HTTP. Los fixtures ejecutables están en `service/service_test.go`, `attestation/attestation_test.go` y `awsstore/*_test.go`; sus claves sintéticas y verificadores permisivos son solo de prueba, nunca política de producción.
