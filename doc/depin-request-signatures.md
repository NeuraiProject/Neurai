# DePIN RPC 3: firmas completas de peticiones y respuestas

Fecha: 2026-10-22. Base revisada:
`1320936c00402befba337aaf7864ff524bce6105`.

**Estado: implementado en el nodo sobre esta base.** El servicio está en testnet:
primero se incorpora el cambio al nodo y después se actualizan las librerías y
aplicaciones. Protocolo **3**, sin aceptar formatos o firmas del protocolo 2 en
las operaciones migradas. El contrato ejecutable está en `depinrpc.cpp` y
`rpc/depin.cpp`; los resultados y límites de validación se conservan en la
[entrega P2](../NIP/NIP_SIN_NUMERO/actualizacion-depin-evidencias-20261021/p2/README.md).

## Alcance y migración

P2 autentica la operación y sus parámetros efectivos, además de comprobar los
permisos vigentes de P3. Abarca solicitud de challenge, lectura, listado personal
de secciones, administración y envío remoto. La lectura por secuencia adopta el
mismo esquema aunque su firma actual ya vincula sus parámetros. Los antiguos
prefijos GET/CLEAR/REQ y READ-SEQUENCE-v1 no son vías alternativas de ejecución.

La versión RPC es independiente de la versión del almacenamiento P9b, del cursor
y del cifrado de los mensajes. P2 no requiere volver a cifrar el histórico ni
cambiar su firma de contenido. Nodo y helpers de wallet se actualizan juntos;
las librerías externas permanecen para la fase posterior acordada. Hasta su
actualización, los clientes antiguos reciben rechazo de protocolo, no una
operación parcialmente compatible. No se incluye un interruptor para recuperar
las firmas débiles.

## Identidad y contexto de servicio

Cada petición se vincula a:

- Versión 3, método RPC exacto y clase de autenticación.
- Hash del génesis de la red, desde `GetConsensus().hashGenesisBlock`.
- Clave pública comprimida del pool y raíz configurada.
- `instance_id` aleatorio de 32 bytes, nuevo al arrancar, restablecer/cambiar la
  clave del pool o detectar cualquier retroceso del reloj.
- `request_id` aleatorio de 32 bytes, nuevo para cada operación del cliente.
- Timestamp Unix en milisegundos, dirección, ámbito y challenge cuando proceda.
- Argumentos efectivos normalizados con el esquema específico del método.

Dos nodos diferentes requieren peticiones firmadas para cada destino. El cliente
puede conservar el mismo mensaje de contenido, preparar un sobre para cada pool
y firmar ambas operaciones. Compartir la clave del pool entre réplicas no
comparte `instance_id` ni convierte los nonces en autorizaciones transferibles.
Los helpers locales reciben la identidad del destino: no presuponen que el
nodo que aloja la wallet sea el nodo receptor.

## Transporte y representación canónica

Cada RPC remoto migrado recibe un objeto de petición, en lugar de combinar los
argumentos posicionales antiguos con reglas nuevas. Claves comunes:
`protocol`, `network`, `pool_pubkey`, `pool_root`, `instance_id`, `request_id`,
`timestamp_ms`, `token`, `address`, `challenge`, `args`, `signature`.
El método y la clase se reconstruyen desde el RPC ejecutado; no se confía en un
nombre de método enviado dentro de `args`.

Se rechazan claves desconocidas o duplicadas en los objetos de la petición y en
el cursor. Los campos requeridos no admiten null. Solo los opcionales definidos
por cada esquema admiten omisión/null y se sustituyen por su valor efectivo
antes de firmar. Se rechazan conversiones implícitas de booleanos, números en
cadenas, fracciones y notación exponencial para campos enteros. El CLI convierte el objeto como JSON, sin reinterpretar sus números. Los
enteros son int64; un cliente JavaScript debe conservarlos sin pérdida por
encima de 2^53. Texto ASCII imprimible: raíz/token hasta 128 bytes, dirección
hasta 64, firma Base64 hasta 128. Identificadores de 32 bytes: 64 caracteres
hexadecimales; clave comprimida: 66. No se permiten campos comunes adicionales.

La preimagen no depende de serializar de nuevo JSON. Se define:

- `U8`, `U16`, `U32`: enteros sin signo de ancho fijo, little-endian.
- `I64`: entero de 64 bits little-endian, representación de complemento a dos.
- `B(x)`: `U32(len(x))` seguido de los bytes exactos de `x`.
- `S(x)`: `B(x)` para texto ASCII. Métodos, assets y direcciones no se recortan ni
  se convierten silenciosamente de mayúsculas/minúsculas.
- `H(x)`: 32 bytes decodificados del hexadecimal mostrado, de izquierda a
  derecha; no la serialización interna invertida de `uint256`. Hexadecimal
  entrante estricto y minúsculo, sin prefijos ni espacios.
- Claves públicas: 33 bytes comprimidos válidos. Nonces: `B` de 0 o 32 bytes.

En orden fijo:

```text
R = S("Neurai/DePIN/RPC/request") || U16(3) || S(method) || U8(auth_kind)
    || H(network) || B(pool_pubkey) || S(pool_root) || H(instance_id)
    || H(request_id) || I64(timestamp_ms) || S(token) || S(address)
    || B(challenge) || B(method_args)
request_hash = SHA256(R)
preimage = "DEPIN-RPC-REQUEST-v3|" + lowercase_hex(request_hash)
```

Se conserva el esquema secp256k1 de firma compacta recuperable y Base64 que usa
`SignDepinChallengePreimage`: la firma de mensaje aplica su magic y hash actuales
a este texto. `request_hash` es SHA256 simple con salida hexadecimal directa,
no el `ToString()` de un hash interno. La firma no forma parte de `R`.

Clases: `0=public`, `1=timestamp`, `2=receive`, `3=admin`. Las clases 2/3 requieren
un nonce emitido para dirección, ámbito y tipo; la clase 1 utiliza ventana de
frescura y registro de replay. Dirección/challenge/firma vacíos son obligatorios
para clase pública; no abren una variante pública de un método privado.

## Esquemas de operaciones

Todos los campos comunes se incluyen incluso si su valor es el vacío definido.
Los argumentos específicos se concatenan en este orden, sin etiquetas JSON:

| Método / variante | Clase | `token` y argumentos canónicos |
|---|---|---|
| `depinchallenge` | timestamp | Ámbito exacto; `U8(type)` con `0=receive`, `1=admin` |
| `depinreceivemsg` | receive | Ámbito exacto; `I64(timestamp)`, `B(after_hash)`, `I64(limit)`; defaults 0, vacío, 0; timestamp >=0, limit 0..1000 |
| `depinreceiveseq` | receive | Ámbito exacto; `U8(continuation)`, `H(stream_id)`, `I64(after_seq)`, `I64(limit)`, `I64(from_timestamp)`; primera página usa flag 0, stream cero, secuencia 0; defaults 100 y 0; limit 1..1000, secuencia/filtro >=0 |
| `depinlistsections`, personal | receive | Ámbito exacto; sin argumentos adicionales |
| `depinclearmsg` | admin | Ámbito normalizado; `U8(mode)`, `I64(hours)`; `0=expired`, `1=all`, `2=hours`; hours obligatorio 0..floor(INT64_MAX/3600) solo en modo 2, cero en los demás |
| `depinsubmitmsg` | timestamp | Token común vacío; `B(bytes del sobre ECIES exterior)` |
| `depingetancestorrecipients` | public | Token consultado; `I64(max_results)`, `S(stop_at efectivo)`; max_results por defecto 1000, rango 1..10000; stop_at omitido/null/vacío se resuelve a la raíz |
| `depinlistsections`, público | public | Raíz del pool, sin argumentos; no devuelve contadores personales |
| `depinpoolstats`, `depinmcpstatus` | public | Raíz del pool, sin argumentos |

El `timestamp` de lectura antigua se firma tal como lo expresa la API antes de
aplicar su ajuste inclusivo de un segundo. La continuación de secuencia incluye
los seis campos de su cursor actual, normalizados: versión 1, stream, secuencia,
ámbito, dirección y filtro. Su ámbito/dirección/filtro deben coincidir con los
de la operación; no basta con que el objeto tenga seis claves cualesquiera.

En administración, el ámbito vacío permitido por la interfaz se resuelve a la
raíz antes de firmar. `expired`, `all` y `hours=0` son tres intenciones distintas;
ninguna firma sirve para otra. El modo por defecto firma explícitamente
`expired`, nunca una ausencia ambigua. No se cambia la semántica temporal del
borrado por horas.

En envío, el token común vacío evita revelar fuera del ECIES la sección que hoy
viaja dentro del sobre. La firma de operación cubre todos los bytes del sobre;
la firma interna sigue cubriendo contenido y metadatos. Después de descifrar se
comprueban remitente, ámbito y permisos actuales de todos los participantes como
ahora. La firma interna por sí sola ya no autoriza un envío RPC v3, y la firma
exterior no autoriza contenido que falle la validación interna.

Las consultas públicas no necesitan una clave de usuario: el servidor vincula
su respuesta firmada a la consulta exacta y al `request_id`. Eso permite detectar
parámetros alterados por un proxy sin convertir información pública en privada.

## Descubrimiento, respuestas y errores

`depingetmsginfo` es el único bootstrap: admite el objeto reducido con versión 3,
request_id y timestamp_ms, para descubrir la identidad antes de poder incluirla
en una petición completa. Para calcular `R`, usa clase pública, network/instance
cero, pool_pubkey vacío, y root/token/address/challenge/args vacíos. Los demás RPC
exigen una identidad explícita que coincida con el servicio actual.

La respuesta de bootstrap anuncia red, clave del pool, raíz, instance_id,
`accepted_protocols: [3]` y `server_time_ms`, dentro de su cuerpo firmado. La firma de esa primera respuesta no sustituye el pinning de
la clave ni la comparación independiente de C1. Una respuesta bootstrap enviada
al destino equivocado debe detectarse contra la identidad esperada por el
cliente, cuando ya la conoce.

Todas las respuestas remotas migradas usan un dominio separado:

```text
Q = S("Neurai/DePIN/RPC/response") || U16(3) || S(method)
    || H(served_network) || B(served_pool_pubkey) || S(served_pool_root)
    || H(served_instance_id) || request_hash || U8(body_kind) || B(body_bytes)
preimage = "DEPIN-RPC-RESPONSE-v3|" + lowercase_hex(SHA256(Q))
```

`body_kind=0` corresponde a JSON público y `1` a ECIES. `body_bytes` son los
bytes decodificados del hex transportado en `body` o `encrypted`, exactamente uno
de esos campos. El wrapper anuncia protocolo, identidad servida, request_hash,
tipo de cuerpo y poolsig. El cliente calcula su propio request_hash y exige que
coincida: no toma el hash recibido como sustituto de su petición original.

El cuerpo contiene directamente el resultado o `{"error": {"code": ...,
"message": ..., "data": {"depin_error": ..., "expected_protocol": 3}}}`. Se
conservan los códigos existentes: por ejemplo `-10` servicio sin frescura, `-26`
destinatario no autorizado y `-20` fallo de almacenamiento del borrado. Las
razones incluyen `unsupported_protocol`, `invalid_parameters`,
`service_mismatch`, `request_expired`, `signature_invalid`, `request_replayed`,
`replay_capacity`, `challenge_invalid`, `rate_limited`, `service_not_ready`,
`service_disabled`, `public_key_unavailable`, `storage_failure` y
`operation_failed`. No todos los rechazos de permisos tienen una razón propia.

Los errores posteriores a normalizar la petición y obtener la clave pública
del usuario se firman y se cifran para esa dirección, incluso si falla su
autenticación. Los fallos anteriores son errores JSON-RPC de transporte: forma,
versión, normalización, servicio no disponible, clave de usuario no revelada o
clave del pool ausente. La barrera de disponibilidad precede a consultar índices
de assets/claves: no se intenta cifrar un error consultando un índice no listo.
No existe respuesta privada de éxito en claro. Un error sin firma no autentica
instrucciones de renovación o migración.

El wrapper tiene exactamente las nueve claves `protocol`, `network`,
`pool_pubkey`, `pool_root`, `instance_id`, `request_hash`, `body_kind`,
`body` **o** `encrypted`, y `poolsig`. Verificar clave fijada, hash local, firma,
forma y confidencialidad antes de interpretar el cuerpo. Para un resultado,
exigir también la identidad/instancia solicitada; un cambio exige bootstrap
verificado y una petición nueva. Un cliente que interprete un error firmado de
instancia distinta debe limitarlo a diagnóstico, verificar la clave ya fijada y
su request_hash local, y jamás tratarlo como éxito o cambiar el pin.

## Replay, consumo y fallos

Las peticiones autenticadas admiten timestamp_ms en la ventana inclusiva
±60000 ms del reloj del servidor. Bootstrap y consultas públicas no aplican
esa ventana: la respuesta firmada se correlaciona con el request_id aleatorio
nuevo y el hash local de la consulta, y siguen disponibles para diagnóstico con
relojes desajustados. El cliente puede usar el server_time_ms recién verificado
para preparar peticiones privadas; no reutilizar información de hora indefinidamente.
Se conservan los TTL de challenge de 30/300 s. `request_id`
se firma en todos los métodos y correlaciona las respuestas. Solicitudes de
challenge y envíos llevan además registro acotado de los request_hash aceptados;
los nonces de lectura/admin siguen siendo de un solo uso, atómicamente.
El registro admite 10000 entradas y rechaza nuevas si está lleno, sin expulsar
entradas protegidas. Cada entrada dura hasta timestamp_ms + 60000 incluido,
que puede ser 120 s desde la admisión si la petición venía del límite futuro.
La poda usa un índice ordenado de expiraciones y no escanea el registro completo
en cada consulta. Replay/capacidad se comprueban antes de consumir cuota; solo
una petición autenticada y autorizada entra en el registro.

El reinicio cambia instance_id: ni las firmas temporizadas antiguas ni los
challenges previos vuelven a ser utilizables. Cualquier retroceso del reloj observado al entrar en un RPC rota instance_id
y borra challenges/replay antes de autorizar. Un reloj detenido no elimina
entradas protegidas; un salto hacia delante las poda, y un posterior retroceso
rota la instancia. La hora de la comprobación inicial se captura una sola vez
bajo cs_main, también para comprobar el challenge. No se declara protección de replay tras rollback de una
imagen completa del proceso en ejecución.

Forma, versión, identidad, argumentos, firma y permisos se verifican antes de
consumir nonces o ejecutar operaciones. Una petición alterada o inválida no
consume el challenge de otra petición válida ni la cuota de una dirección
suplantada. Lectura/admisión/borrado conservan la coherencia de P3 bajo cs_main.
Una firma válida no evita que después falle el almacenamiento o el envío de la
respuesta; eso puede consumir el nonce y dejar resultado desconocido para el
cliente. Se exige recuperación explícita con reintentos acotados, sin prometer
entrega exactamente una vez.

## Coordinación con P7 y trabajo pendiente

P7 fase 1 puede añadir información de revisión al cuerpo ya firmado de las
respuestas. No se inventa una revisión actual ni se invalidan todas las sesiones
por cada bloque como parte de P2. Si se aprueba una fase 2 que exija contexto en
la petición, ese contexto deberá entrar en el esquema firmado y anunciarse
explícitamente: no se aceptará como campo exterior sin firmar.

## Uso del RPC y helpers

Cada método remoto recibe **un** parámetro `request`, mediante `[objeto]` o
`{"request": objeto}` en JSON-RPC. Bootstrap:

```json
{"protocol":3,"request_id":"<32 bytes aleatorios en hex minúsculo>","timestamp_ms":1792660000000}
```

Objeto completo (los marcadores deben sustituirse por valores válidos):

```json
{
  "protocol":3,"network":"<génesis>","pool_pubkey":"<clave fijada>",
  "pool_root":"&GROUP","instance_id":"<instancia verificada>",
  "request_id":"<32 bytes aleatorios nuevos>","timestamp_ms":1792660000000,
  "token":"&GROUP/SEC","address":"<dirección Legacy>",
  "challenge":"<nonce de recepción>","args":{"cursor":null,"limit":100,"from_timestamp":0},
  "signature":""
}
```

En la wallet local desbloqueada, `depinsignrpc "depinreceiveseq" objeto`
devuelve `request` con firma, `preimage` y `request_hash`. El destino es el del
objeto; puede ser distinto del nodo de la wallet. Enviar ese request al RPC
remoto con el mismo método. El helper firma el objeto solicitado, no comprueba
que el destino remoto sea honesto ni contacta con él. No exponerlo en el proxy.

`depinsignrequest`, `depinsignchallenge` y `depinsignreadseq` han desaparecido de
la tabla RPC. Permanecen locales `depinsendmsg`, `depingetmsg`, `depindecrypt` y
`depinpoolpkey`; el bot interno utiliza admisión/lectura locales y mantiene sus
comprobaciones de permisos. No hay fallback público a firmas antiguas.

## Vectores y validación

- [13 vectores de peticiones](../src/test/data/depin_rpc_v3.json) con bytes,
  SHA256 y preimagen, generados por [Python struct/hashlib independiente](../contrib/devtools/depin-v3-vectors.py).
- [Pruebas C++](../src/test/depinrpc_tests.cpp): codec, defaults/null, enteros,
  duplicados, cursor, respuesta, capacidad, reloj y replay concurrente.
- [Cliente funcional independiente](../test/functional/test_framework/depin.py):
  reconstruye preimágenes sin llamar al codec C++, compara el firmante de wallet
  con signmessage y verifica respuestas antes de descifrar. Es infraestructura de
  pruebas, no una librería externa ya migrada.
- [Regresión RPC real](../test/functional/feature_depin_request_signatures.py):
  parámetros/métodos/identidad alterados, formatos antiguos, duplicados HTTP,
  concurrencia, reinicio y reloj; complementada por los regtests de permisos y
  estado, y el rechazo firmado de un borrado que supera la capacidad de marcas.

No se cambia consenso, minería, P2P, cifrado de contenido, formato de estado 2 ni
cursor 1. No se vuelve a ejecutar aquí el ensayo físico de disco lleno de P8:
se conserva su evidencia anterior y se añade el error RPC por capacidad con
protocolo 3. Tampoco se certifican todas las posibilidades de fallo, GUI,
configuración desplegada del proxy, carga de producción o librerías externas.

P7 informativo y las librerías/aplicaciones externas siguen pendientes. P2 no
convierte un directorio firmado en una prueba de posesión de assets: mantener
la comparación independiente y la política de destinatarios de C1. El robo de
una clave Legacy puede exponer mensajes históricos cifrados para ella; la clave
ECIES efímera y la rotación de las respuestas no proporcionan secreto hacia
delante frente al robo de esa clave de destinatario.
