# Revisión de código — rama `DePIN-Test`

**Fecha:** 2026-06-10
**Alcance:** 240 commits que separan `DePIN-Test` de `origin/main`
(`git log --oneline origin/main..DePIN-Test`).
**Método:** revisión repartida en seis frentes (intérprete/opcodes, consenso/chainparams,
criptografía, policy/mempool/validación, subsistema DePIN/MCP, PQ/RPC/wallet). Los hallazgos
marcados como **verificado directamente** se confirmaron leyendo el código fuente con las líneas
citadas; el resto procede de revisión asistida que afirma haber verificado en el código antes de
reportar.

---

## Resumen ejecutivo

Lo positivo:

- **La criptografía nueva está sólida.** El wrapper strict-profile de ed25519, Poseidon, SHA3/Keccak,
  Blake2b y BLAKE3 se validaron contra vectores externos reales (RFC 8032, Wycheproof, FIPS-202,
  vectores de circomlib/iden3) con **0 desviaciones**.
- **El gating de mainnet es correcto hoy.** Las 26 opt-ins de consenso están en `false` en mainnet
  y NIP-028 está fijado a `INT_MAX`. Ninguna de las funcionalidades nuevas activa en mainnet
  actualmente.

El problema central: **varios cambios pensados para testnet se escapan de su sandbox** (afectan
mainnet en IBD/reindex o pueden borrar datos de mainnet) o son **inconsistentes con la propia
doctrina del proyecto**. Hay además una superficie de red nueva (DePIN) con problemas serios de
autenticación y ciclo de vida.

| # | Severidad | Área | Resumen |
|---|-----------|------|---------|
| 1 | 🔴 Crítico | Intérprete | OP_CAT se ejecuta dentro de ramas IF no tomadas |
| 2 | 🔴 Crítico | Intérprete | Cluster de opcodes hace fallback a NOP con flag apagado |
| 3 | 🔴 Crítico | Consenso/operación | Epoch-reset de testnet roto; puede borrar datos de mainnet |
| 4 | 🔴 Crítico | Consenso | `AreAssetsDeployed`/`IsRip5Active` alteran consenso de mainnet en IBD |
| 5 | 🔴 Crítico | DePIN/red | Puerto DePIN sin auth ejecuta comandos privilegiados |
| 6 | 🔴 Crítico | DePIN/ciclo de vida | Servidor DePIN nunca se detiene → use-after-free en shutdown |
| 7 | 🔴 Crítico | Wallet PQ | `-pqwallet` + `-bip44=0` genera claves idénticas |
| 8 | 🟠 Medio | Validación | OP_INPUTVALUE depende del flag equivocado |
| 9 | 🟠 Medio | Consenso | Validación de bloque consulta el mempool vivo |
| 10 | 🟠 Medio | Consenso | Tightening retroactivo de OP_XNA_ASSET sin gating |
| 11 | 🟠 Medio | Operación | Fix de `fscanf` aplicado en un solo lector de época |
| 12 | 🟠 Medio | DePIN | API key MCP enviada en claro (sin TLS) |
| 13 | 🟠 Medio | DePIN | `messageType` no está cubierto por la firma |
| 14 | 🟠 Medio | Wallet/cripto | Seed maestro y material PQ sin zeroizar |
| 15 | 🟠 Medio | Policy | Defaults de mempool subidos también en mainnet |
| 16 | 🟠 Medio | Intérprete/DoS | OP_CHECKSIG_ED25519 no cuenta para el presupuesto de sigops |
| 17 | 🟠 Medio | Consenso/arranque | Minería de génesis SHA256 depende de `bNetwork` ya inicializado |
| 18 | 🟠 Medio | Wallet PQ | Estado global del RNG de liboqs frágil ante excepciones/hilos |
| 19 | 🟠 Medio | DePIN/RPC | Mensajes vía gateway se almacenan con firma a ceros |
| — | 🟡 Bajo | Varios | Comentarios desactualizados, hygiene, logs en claro, DoS de bajo impacto (ver §Bajos) |

---

## Críticos

### 1. OP_CAT se ejecuta dentro de ramas `IF` no tomadas — *verificado directamente*

**Archivo:** `src/script/interpreter.cpp:594`

El handler de OP_CAT corre en la línea 594, *antes* del guard `fExec` (líneas 635/643). Todos los
demás opcodes solo se ejecutan cuando `fExec` es `true` (rama actualmente activa). El OP_CAT hace
`continue` en la línea ~616, sin pasar por el guard.

```cpp
// interpreter.cpp:594
if (opcode == OP_CAT && (flags & SCRIPT_VERIFY_CAT)) {
    ... // pop/concat/push
    continue;        // <- salta el switch y el guard fExec
}
...
// interpreter.cpp:635
if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) ...
else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)) ...
```

**Consecuencia:** con `SCRIPT_VERIFY_CAT` activo, un script como
`OP_0 OP_IF OP_CAT OP_ENDIF OP_1` debería *saltar* el OP_CAT y tener éxito, pero esta
implementación lo ejecuta igualmente: opera sobre el stack del contexto externo o falla con
`SCRIPT_ERR_INVALID_STACK_OPERATION` / `PUSH_SIZE`. Diverge de BIP-347 (donde OP_CAT vive dentro
del switch de opcodes ejecutados) y de la propia documentación de la rama.

**Riesgo:** consenso. No hay test que cubra OP_CAT en rama no ejecutada (`src/test/opcat_tests.cpp`).

**Sugerencia:** mover el manejo de OP_CAT dentro del switch de opcodes ejecutados, sujeto al guard
`fExec` como cualquier otro opcode.

---

### 2. Cluster de opcodes hace fallback a NOP cuando su flag está apagado — *verificado parcialmente*

**Archivo:** `src/script/interpreter.cpp` (bytes `0xbc`, `0xc5`, `0xcc`–`0xd6`)

La doctrina del proyecto, documentada extensamente en el handler de NIP-026
(`interpreter.cpp:1051-1065`), establece que un byte de opcode recién asignado debe devolver
`SCRIPT_ERR_BAD_OPCODE` cuando su flag está apagado:

> "un nodo nuevo con el flag apagado lo ejecutaría como NOP, aceptando txs que los nodos
> pre-upgrade rechazan — un split de consenso".

Los handlers más nuevos (NIP-030/031/035/039, CHAINCONTEXT) cumplen esta regla. Sin embargo, un
grupo de opcodes de introspección más antiguos hace `break` (comportamiento NOP) en vez de
`BAD_OPCODE` cuando su flag está off, pese a ocupar bytes que en `origin/main` estaban igualmente
sin asignar:

| Opcode | Byte | Línea aprox. |
|--------|------|--------------|
| OP_REVERSEBYTES | 0xbc | 939 |
| OP_TXLOCKTIME | 0xc5 | 1420 |
| OP_OUTPUTVALUE | 0xcc | 956 |
| OP_OUTPUTSCRIPT | 0xcd | 988 |
| OP_OUTPUTASSETFIELD | 0xce | 1188 |
| OP_INPUTASSETFIELD | 0xcf | 1229 |
| OP_INPUTCOUNT | 0xd0 | 1270 |
| OP_OUTPUTCOUNT | 0xd1 | 1287 |
| OP_REFINPUT* | 0xd2–0xd4 | 1307 |
| OP_OUTPUTAUTHCOMMITMENT | 0xd5 | 1163 |
| OP_INPUTVALUE | 0xd6 | 1021 |

> Nota: OP_SPLIT/OP_TXFIELD/OP_TXHASH/OP_CHECKSIGFROMSTACK/OP_CHECKTEMPLATEVERIFY (0xb3–0xb7) **sí**
> son reutilización de NOP4–NOP8, por lo que el fallback a NOP ahí es correcto.

**Riesgo:** consenso. Asimétrico con la propia regla del proyecto. Puede ser intencional (si solo
activan vía hardfork, el caso "flag off en red viva" no ocurre), pero el código contradice su
doctrina documentada.

**Sugerencia:** confirmar con el equipo. Si no es intencional, devolver `BAD_OPCODE` con flag off
en estos slots.

---

### 3. Epoch-reset de testnet roto; riesgo de borrar datos de mainnet — *verificado directamente*

**Archivos:** `src/validation.cpp:3387` (escritura) vs `src/neuraid.cpp:116` y `src/qt/neurai.cpp:700` (lectura)

El marcador de reset se **escribe** con `GetDataDir()` (específico de red, p.ej.
`<datadir>/testnet/testnet_reset`):

```cpp
// validation.cpp:3387 (UpdateTip)
fs::path markerFile = GetDataDir() / "testnet_reset";
```

…pero se **lee** con `GetDataDir(false)` (datadir base, `<datadir>/testnet_reset`):

```cpp
// neuraid.cpp:116
fs::path dataDir    = GetDataDir(false);
fs::path markerFile = dataDir / "testnet_reset";
```

**Consecuencia 1 (funcional):** el marcador nunca se encuentra, así que el incremento de época y el
wipe jamás corren. Cada nodo de testnet simplemente se apaga una vez al alcanzar
`TESTNET_EPOCH_LENGTH` y arranca normal al reiniciar — quedando permanentemente desincronizado del
diseño documentado de reset.

**Consecuencia 2 (destructiva):** si alguna vez aparece un marcador en la ruta base (creación
manual, o un futuro fix unilateral), el `fs::remove_all(dataDir / "blocks")` / `"chainstate"` con
`dataDir = GetDataDir(false)` **borra la base de bloques de mainnet**, porque mainnet guarda
directamente en el datadir base.

**Sugerencia:** unificar ambos lados a la misma ruta (la específica de red), y añadir una guarda que
impida ejecutar el wipe si la red activa no es testnet.

---

### 4. `AreAssetsDeployed()` / `IsRip5Active()` alteran el consenso de mainnet en IBD

**Archivo:** `src/validation.cpp:6113` y `:6133`

El nuevo atajo activa los assets en cuanto `chainActive.Height() >= nAssetActivationHeight`, y en
mainnet ese valor es **10** (`src/chainparams.cpp:308`). En `origin/main` esta función dependía solo
del estado BIP9 del `DEPLOYMENT_ASSETS`, que en mainnet activó miles de bloques después del génesis.

**Consecuencia:** un IBD/reindex limpio de mainnet con este binario aplicaría todas las reglas
gateadas por `AreAssetsDeployed()` (validación de scripts de asset en `CheckTransaction`/
`CheckTxAssets`, `GetMaxBlockSerializedSize`, etc.) desde el bloque 10 en vez de la altura
histórica — cambio retroactivo que arriesga validar/rechazar de forma distinta bloques históricos.

Además `IsRip5Active` usa `>=` mientras el hermano `IsMessagingActive` usa `>` para el mismo
parámetro de activación → off-by-one entre ambos predicados.

**Riesgo:** consenso en mainnet.

**Sugerencia:** mantener la dependencia del estado de deployment, o gatear el atajo por red para que
no afecte mainnet.

---

### 5. Puerto DePIN sin autenticación ejecuta comandos privilegiados — *verificado directamente*

**Archivos:** `src/depinmsgpoolnet.cpp:152` (bind), `:555` (auth), `:615-630` (dispatch)

El servidor DePIN hace `bind` a `INADDR_ANY` (todas las interfaces, no localhost):

```cpp
// depinmsgpoolnet.cpp:152
serverAddr.sin_addr.s_addr = INADDR_ANY;
```

Solo `depinsendmsg`/`depingetmsg` pasan por challenge + firma:

```cpp
// depinmsgpoolnet.cpp:555
if (jsonRequest.strMethod == "depinsendmsg" || jsonRequest.strMethod == "depingetmsg") {
    // ... ValidateChallenge + VerifyChallengeSignature
}
```

Todo lo demás cae al `else` **sin autenticación**, incluyendo:

- `depinclearmsg` → vacía toda la pool de mensajes (`pDepinMsgPool->Clear()`)
- `depingetpoolcontent` → vuelca todos los mensajes de la pool a cualquier llamante

**Consecuencia:** un atacante remoto puede enviar `{"method":"depinclearmsg","params":["all"]}` y
borrar la pool entera, o leer todo el contenido. Es una superficie tipo-admin expuesta a la red.

**Sugerencia:** restringir el bind a localhost por defecto, y exigir el mismo challenge+firma (o un
token de admin) para todos los métodos que muten o lean contenido sensible.

---

### 6. Servidor DePIN nunca se detiene en el shutdown → use-after-free

**Archivos:** `src/init.cpp` (Shutdown), `src/depinmsgpoolnet.cpp:250`

En el apagado se detiene el worker MCP y se guarda la pool, pero nunca se llama a
`pDepinMsgPoolServer->Stop()` ni `.reset()`. El hilo listener sigue en `accept()` y los handlers de
cliente corren en hilos **detached** (`depinmsgpoolnet.cpp:250-251`) que dereferencian
`pDepinMsgPool`, `pblocktree`, `passetsdb`, `vpwallets[0]`.

**Consecuencia:** durante el teardown esos globales se liberan (chainstate/wallet destruidos)
mientras los handlers detached en vuelo siguen accediéndolos → race / use-after-free. Además, los
hilos por conexión no se trackean ni se limitan (un hilo por conexión, sin tope) → flood de
conexiones = DoS.

**Sugerencia:** detener explícitamente el servidor al inicio del Shutdown (antes de liberar
chainstate/wallet), hacer join de los handlers en vuelo, y poner un límite de conexiones
concurrentes.

---

### 7. `-pqwallet` con `-bip44=0` genera claves idénticas en cada wallet

**Archivo:** `src/wallet/wallet.cpp:780-833` (`GenerateNewKeyPQ`), `:773-778` (`GetMasterExtKeyPQ`)

Las claves PQ derivan del global `g_vchSeed` vía
`CExtKeyPQ::SetSeed(g_vchSeed.data(), g_vchSeed.size())`. Pero `g_vchSeed` solo se rellena en la ruta
BIP44 (mnemónico / `DecryptBip39`). En la rama HD no-BIP44, `g_vchSeed` queda **vacío**, y
`IsPQEnabled()` solo exige `IsHDEnabled() && bUsePQ` (`wallet.cpp:1889`), con `UsePQ(true)` fijado
independientemente de `-bip44` (`wallet.cpp:5048`).

**Consecuencia:** `CExtKeyPQ::SetSeed(ptr, 0)` hace HMAC de un mensaje vacío bajo una clave fija →
`pq_seed` fijo → **toda wallet `-pqwallet -bip44=0` en una red dada genera las mismas direcciones y
claves**. No hay guarda que fuerce PQ⇒BIP44. Condicionado a configuración, pero catastrófico (reuso
de claves / pérdida de fondos) cuando ocurre.

**Sugerencia:** forzar PQ⇒BIP44, o abortar con error si `g_vchSeed` está vacío al generar claves PQ.

---

## Medios

### 8. OP_INPUTVALUE depende del flag equivocado

**Archivo:** `src/validation.cpp:1860`

Los prevouts (`pAllPrevouts`) se construyen solo `if (flags & SCRIPT_VERIFY_INPUTASSETFIELD)`, pero
`GetInputValue` (`src/script/interpreter.cpp:3252`) falla en cerrado sin `m_allPrevouts`, y el
handler de OP_INPUTVALUE se gatea con `SCRIPT_VERIFY_INPUTVALUE`. Si una red activa NIP-024 sin
NIP-022 (params independientes), todo script con OP_INPUTVALUE falla con `SCRIPT_ERR_INPUTVALUE`.
Hoy enmascarado porque testnet/regtest activan ambos y mainnet ninguno — trampa latente para una
futura activación en mainnet.

**Sugerencia:** la guarda debería ser
`flags & (SCRIPT_VERIFY_INPUTASSETFIELD | SCRIPT_VERIFY_INPUTVALUE)`.

### 9. Validación de bloque consulta el mempool vivo

**Archivo:** `src/consensus/tx_verify.cpp:103` (`GetAssetMetadataForTransfer`), llamado desde
`Consensus::CheckTxAssets` (`:927`) que corre dentro de `ConnectBlock` (`src/validation.cpp:2803`).

La validez de un bloque ("bad-txns-transfer-asset-not-exist" / checks de unidades) puede depender
del contenido del mempool local → nodos con mempools distintos pueden discrepar sobre un bloque.
Además accede a `mempool.mapAssetToHash` sin tomar `pool.cs`. El helper ignora el parámetro
`fCheckMempool` existente, que era exactamente el interruptor previsto para esto.

### 10. Tightening retroactivo de OP_XNA_ASSET sin gating

**Archivo:** `src/consensus/tx_verify.cpp:684` y `:1063`

Tras el test `HasAssetOpcodeInExpectedPosition` se añadió un `return state.DoS(100, ...)`
**incondicional** (no gateado por `AreAssetsDeployed`). La regla vieja aceptaba outputs cuyo script
empieza por `OP_XNA_ASSET` (0xc0) aunque no fuesen parseables como script de asset; la nueva los
rechaza. Aplica retroactivamente a todo el historial de mainnet en IBD/reindex.

### 11. Fix de `fscanf` aplicado en un solo lector de época

**Archivos:** `src/neuraid.cpp:122`, `src/qt/neurai.cpp:705`

El fix del commit 3a4add3 (chequear el retorno de `fscanf`) se aplicó solo en `chainparams.cpp`. Los
otros dos lectores siguen con `fscanf(f, "%u", &nEpoch);` sin chequear retorno. Ningún lector valida
cota superior de época (overflow teórico de `TESTNET_BASE_TIME + nEpoch` en uint32), `%u` acepta
negativos por wraparound, y un fichero con basura final ("3junk") parsea como válido.

### 12. API key MCP enviada en claro (sin TLS)

**Archivo:** `src/depinmcpclient.cpp:119-225, 283-358`

`MakeHTTPRequest`/`FetchModelName` usan `evhttp_connection_base_new`, que es TCP plano. Con una URL
`https://` configurada, el puerto resuelve (443) pero la conexión sigue siendo HTTP plano y el header
`Authorization: Bearer <key>` se transmite sin cifrar. No hay ruta TLS.

### 13. `messageType` no está cubierto por la firma

**Archivo:** `src/depinmsgpool.cpp:525-530` (`SignDepinMessage`)

La firma hashea `token|senderAddress|timestamp|encryptedPayload` y omite `messageType`.
`VerifyDepinMessageSignature` intenta el formato nuevo (con `messageType`) y hace fallback al viejo
(sin). Como el firmado siempre emite el formato viejo, `messageType` queda efectivamente sin
autenticar/maleable: un relay puede cambiar un mensaje privado (0x01) a grupo (0x02), alterando el
filtrado de acceso en `GetMessagesForAddress`. La confidencialidad (ECIES) se mantiene; el control
de acceso/integridad no.

### 14. Seed maestro y material PQ sin zeroizar

**Archivos:** `src/keystore.h:96`, `src/wallet/crypter.cpp:162-177`, `src/key.cpp:453`

`g_vchSeed` es `std::vector<unsigned char>` normal (no `secure_allocator`) y `Lock()` no lo limpia.
Tras el primer unlock/`DecryptBip39` el seed raíz (de todo el árbol EC y PQ) persiste en claro y sin
zeroizar en el heap durante toda la vida del proceso. Además `CExtKeyPQ::GetKey()` (`key.cpp:453`)
copia el `pq_seed` seguro a un `std::vector` normal que se destruye sin limpieza.

### 15. Defaults de mempool subidos también en mainnet

**Archivo:** `src/validation.h:82-88`

Límites de ancestros/descendientes 200→500 y tamaño 250→750 KB. Es policy, no consenso, pero es un
cambio que afecta mainnet colado junto con trabajo de testnet (commit 21a127e).

### 16. OP_CHECKSIG_ED25519 no cuenta para el presupuesto de sigops

**Archivo:** `src/script/script.cpp:202-224` (`GetSigOpCount`), `src/script/interpreter.cpp:590, 2188`

`CScript::GetSigOpCount` solo cuenta `OP_CHECKSIG[VERIFY]` y `OP_CHECKMULTISIG[VERIFY]`. Los opcodes
de verificación de firma nuevos no contribuyen al presupuesto de sigops por tx/bloque.
OP_CHECKSIGADD compensa internamente con `nOpCount += CHECKSIGADD_PQ_SIGOP_COST`
(`interpreter.cpp:2188`), pero **OP_CHECKSIG_ED25519 no tiene recargo alguno** — solo paga el
`++nOpCount` genérico de cada opcode (`interpreter.cpp:590`). Un script puede empaquetar ~200
verificaciones Ed25519 dentro de `MAX_OPS_PER_SCRIPT`.

**Riesgo:** DoS de bajo impacto (Ed25519 es barato, ~75 µs/verify), pero es inconsistente con la
filosofía de presupuesto que sí aplican Poseidon y CHECKSIGADD, y con el límite de sigops de bloque
basado en `GetSigOpCount`. Conviene confirmar si la omisión es intencional.

### 17. Minería de génesis SHA256 depende de `bNetwork` ya inicializado

**Archivo:** `src/chainparams.cpp:747-754, 444`, `src/primitives/block.cpp:14-19`

`bNetwork.SetNetwork()` (que fija `fSHA256Mining` para testnet) corre antes de `CreateChainParams`
solo para los llamantes que fuerzan red (`neuraid.cpp:139`, `qt/neurai.cpp:722`). Pero
`src/neurai-tx.cpp:49` y `src/qt/paymentserver.cpp:229` llaman a `SelectParams(...)` con el
`fForceBlockNetwork=false` por defecto: el bucle de minería de génesis del constructor de
`CTestNetParams` (`chainparams.cpp:444`) usa entonces la ruta X16Rv2 `GetHash()` a target
0x1e00ffff (~2^24 hashes X16Rv2 — minutos de CPU al arrancar) y calcula un hash de génesis que
**difiere** del génesis SHA256d del daemon para la misma época.

**Riesgo:** arranque lento/colgado y posible divergencia de génesis en herramientas auxiliares.

### 18. Estado global del RNG de liboqs frágil ante excepciones/hilos

**Archivo:** `src/key.cpp:176-209` (`MakeNewKeyPQ(seed)`), `:137-149` (variante aleatoria)

`MakeNewKeyPQ(seed)` instala un RNG global del proceso (`OQS_randombytes_custom_algorithm`) que lee
un puntero de seed `thread_local`, y restaura `OQS_RAND_alg_system` **solo en la ruta normal**. La
variante aleatoria `MakeNewKeyPQ()` no selecciona defensivamente el RNG del sistema antes de generar.

**Riesgo:** si una excepción (p.ej. `bad_alloc` en `keydata.resize`) ocurre entre instalar y
restaurar, el global queda en modo "determinista"; una keygen aleatoria posterior en ese hilo
produciría una clave predecible en silencio. Keygen determinista + aleatoria concurrentes dispara
`assert(g_pq_det_seed != nullptr)`. En la práctica está serializado bajo `cs_wallet`, pero el diseño
es inseguro.

### 19. Mensajes vía gateway se almacenan con firma a ceros

**Archivo:** `src/rpc/messages.cpp:765-787` (`depinsendmsg`), `src/depinmsgpoolnet.cpp:608`

Cuando `request.fSkipWalletCheck` está activo (ruta autenticada del gateway), el código hace
`chatMsg.signature.resize(65, 0)` y llama a `AddMessage(chatMsg, error, /*skipSig=*/true)`. El
gateway hace challenge/response primero, pero el mensaje persistido en la pool queda **sin firma
verificable** (`signature_hex` a ceros), de modo que cualquier nodo/cliente que lo lea luego vía
`depinreceivemsg` no puede verificar criptográficamente al remitente — contradiciendo la garantía
"ALWAYS verify signature" que sí impone `depinsubmitmsg` (`messages.cpp:1200-1213`).

Relacionado con el hallazgo #13 (integridad de metadatos del mensaje).

---

## Bajos / cosméticos

- **Comentarios de altura NIP-028 desactualizados:** `src/validation.cpp:1448` y `:1471` dicen
  testnet "23.000"; el valor real es 22.700 (`src/chainparams.cpp:354`).
- **Comentario "stub" falso:** `src/test/ed25519_tests.cpp:12-19` afirma que `VerifyStrict()` es un
  stub y que hay decoradores `EXPECTED_FAILURES`; ninguna de las dos cosas es cierta.
- **Provenance del JSON Wycheproof no auditable:** `src/test/data/wycheproof_ed25519.json` no es un
  artefacto verbatim de Wycheproof (faltan `generatorVersion`/`notes`), aunque sus 150 vectores
  cuadran con OpenSSL.
- **Loads LE-only:** `src/crypto/sha3_256.cpp:28-40` y `src/crypto/ed25519/compat.h:57-69` hacen
  `memcpy` host-endian; en big-endian computarían resultados de consenso incorrectos en silencio.
- **memcpy con `len==0` y puntero nulo:** `src/crypto/sha3_256.cpp:64` (UB técnico; blake2b/blake3 lo
  guardan).
- **Prompt y respuesta del MCP logueados en claro:** `src/depinmcpclient.cpp:241,252` escriben
  contenido (descifrado) de mensajes a debug.log.
- **Log de address/IsMine:** `src/rpc/messages.cpp:958-960` loguea address + IsMine + nombre de
  wallet en cada envío.
- **`O(n²)` en `AddMessage`:** `src/depinmsgpool.cpp:158,365-377` recomputa el uso de memoria
  iterando todos los mensajes en cada inserción.
- **Comentario de tamaño extkey PQ:** `src/key.h:329` dice "73-byte"; el valor real es 74
  (`src/pubkey.h:439`).
- **Vectores PQ-HD solo de consistencia:** `src/test/pq_hd_tests.cpp` cubre determinismo y
  separación de dominio, pero los KATs cross-implementación están comentados como "PENDIENTE".
- **`fPowAllowMinDifficultyBlocks = true` es config muerta en testnet** (`chainparams.cpp:339`): la
  rama que lo honra es inalcanzable con DGW activo.

### Intérprete / consenso (bajos)

- **Operando de cuenta de OP_CHECKSIGADD con límite de 4 bytes** (`interpreter.cpp:2183`):
  `CScriptNum bnCount(vchCount, fRequireMinimal)` usa `nDefaultMaxNumSize` (4), no `nMaxNum` (8 con
  `SCRIPT_VERIFY_64BIT_INTEGERS`) como el resto del switch. Coincide con BIP-342 (probablemente
  intencional), pero es inconsistente con el manejo numérico de 64 bits circundante y `bnCount +
  bnOne` se empuja sin guarda de overflow de 64 bits.
- **Cobertura de `verify_flags_tests` con huecos** (`src/test/verify_flags_tests.cpp:21`): el
  comentario dice "bits 0-33" pero se chequea hasta bit 34; los bits 35-37
  (KECCAK_BLAKE2B/MERKLE_INCLUSION/MODERN_HASHES) no tienen aserción individual de posición. El test
  de cuenta total (`end_marker_matches_flag_count`, 41) detectaría una reordenación global, pero no
  un swap de dos bits adyacentes sin pin.
- **Resultados de OP_OUTPUTASSETFIELD/OP_INPUTASSETFIELD sin cota de tamaño**
  (`interpreter.cpp:1210-1223, 1251-1264`): a diferencia de OP_TXFIELD/OP_OUTPUTSCRIPT/
  OP_REFINPUTFIELD (que re-chequean `EffectiveMaxScriptElementSize` tras el checker), estos empujan
  `vchResult` sin chequeo explícito. Seguro en la práctica (nombres de asset/hashes IPFS muy por
  debajo de 520 B), pero rompe el patrón "elevar el chequeo al llamante" de los demás opcodes de
  introspección.

### Policy / mempool (bajos)

- **Gate de standardness de witness se sobre-amplía para ed25519** (`policy.cpp:290-295`,
  `validation.cpp:763-768`): el cap de stack-item de P2WSH (3072 B) se activa con
  `nCSFSEnabled || nMerkleInclusionEnabled || nEd25519Enabled || nCheckSigAddEnabled`, pero el cap de
  consenso `EffectiveMaxScriptElementSize()` (`interpreter.h:306-313`) solo se amplía para
  `CHECKSIGFROMSTACK | MERKLE_INCLUSION | CHECKSIGADD` — **ED25519 está excluido a propósito**. En una
  red hipotética con solo `nEd25519Enabled`, un item de 521–3072 B pasaría `IsWitnessStandard` pero
  el intérprete lo rechazaría (`SCRIPT_ERR_PUSH_SIZE`). Auto-corregido (se rechaza en admisión, no
  entra al mempool), pero las dos rutas deberían ir en lockstep.
- **Re-validación O(entradas etiquetadas) por OP_CHAINCONTEXT en cada cambio de tip**
  (`validation.cpp:444-481`, `txmempool.cpp:250-269`): re-ejecuta `CheckInputs` (verificación de
  script completa, con caché frío tras rotar el nonce) para cada entrada marcada
  `fUsesChainContext` en cada `ConnectTip`/`DisconnectTip`. Acotado a entradas que ejercitaron el
  opcode, pero un atacante puede forzar un barrido de re-verificación por bloque llenando el mempool
  de txs baratas con OP_CHAINCONTEXT. Gateado por `nCHAINCONTEXTEnabled` (inerte en mainnet).
- **Cap de reemplazos RBF (100) desalineado con el límite de descendientes elevado (500)**
  (`validation.cpp:864` vs `validation.h:84`): `maxDescendantsToVisit = 100` hardcodeado mientras
  `DEFAULT_DESCENDANT_LIMIT` subió a 500. No es bug (coincide con el BIP125 conservador de upstream),
  pero una tx puede acumular hasta 500 descendientes que nunca podrán reemplazarse vía RBF
  ("too many potential replacements"). Inconsistencia conductual que conviene documentar.

### DePIN / cripto (bajos)

- **`conn` filtrado en fallo de `evhttp_make_request`** (`depinmcpclient.cpp:208-213, 348-353`): se
  liberan `uri`/`base` pero no la `evhttp_connection` en las rutas de error. Fuga menor.
- **`LoadFromDisk` no pre-valida el contador** (`depinmsgpool.cpp:952-977`): lee un `uint64 count` y
  hace loop sin la cota de cordura que sí usa el cargador MCP (`depinmcpworker.cpp:749`, tope de
  100000). Depende de que el stream lance en EOF; endurecimiento inconsistente entre ambos
  persistidores.
- **Código cripto muerto / doc inconsistente en ECIES**: `AES256_CBC_Encrypt/Decrypt`
  (`depinecies.cpp:95-182`) están definidos pero sin uso (GCM es la ruta viva); los comentarios de
  `CECIESEncryptedMessage` (`depinecies.h:46-52`) describen `IV(16)||data||HMAC-SHA256(32)` mientras
  el código usa `Nonce(12)||ciphertext||Tag(16)`; `doc/depinreceivemsg.md:77` lista "AES-256-GCM/CBC".
  Cosmético, sin impacto en runtime.
- **Código muerto en el shim de compatibilidad ed25519** (`src/crypto/ed25519/compat.h`): el
  comentario afirma que `crypto_verify_32` se referencia en ref10.c, pero nada en las fuentes
  vendorizadas lo usa; el fallback `COMPILER_ASSERT` en modo C pega el token literal `__LINE__` sin
  doble expansión (todos los usos compartirían un identificador). Actualmente sin uso, pero mordería
  en una futura actualización de ref10.

### Operación (bajos)

- **Comentarios de génesis SHA256d en regtest erróneos** (`chainparams.cpp:633-637`): afirman minería
  SHA256d, pero `fSHA256Mining` se fija solo para `"test"`; el génesis de regtest se mina por la ruta
  X16R/X16Rv2 `GetHash()` (funciona solo por el target 0x207fffff). Desajuste comentario/comportamiento
  y asimetría testnet/regtest.
- **La época no forma parte de la identidad P2P** (`chainparams.cpp`): nodos testnet de épocas
  distintas comparten `pchMessageStart` ("RUEN") y puerto 19100 pero tienen génesis distintos; se
  emparejan y luego se rechazan las cabeceras sin diagnóstico claro. Molestia operativa inherente al
  diseño de épocas.

---

## Verificado y correcto (sin hallazgo)

- Bits de los verify-flags: definición, pins de test, `END_MARKER=41` y el `static_assert`
  (`MAX_SCRIPT_VERIFY_FLAGS_BITS<=63`) son consistentes. Sin colisiones de bits.
- Slots de opcodes sin duplicados; `MAX_OPCODE=OP_CHECKSIGADD=0xde` correcto; 0xd8–0xdc caen a
  `default: BAD_OPCODE`. `GetOpName` cubre todos los opcodes nuevos.
- `script_error.h` ↔ `script_error.cpp`: cada enum nuevo tiene su string.
- `ApplyConsensusOptIns` cubre las 26 booleanas de consenso exactamente una vez y se aplica
  consistentemente en admisión a mempool, flags de bloque (`GetBlockScriptFlags`), re-validación de
  mempool, firmado, `neurai-tx` y `signrawtransaction`. Sin divergencia de flag-sets.
- Matemática de NIP-028: el subsidio se halviza mientras el intervalo se duplica (emisión por
  wall-clock preservada); sin off-by-one en el borde de activación; DGW se ajusta gradualmente en
  ventanas que cruzan la activación.
- Génesis de testnet: assert de hash de génesis correctamente eliminado (génesis dinámico por época);
  merkle-root retenido es invariante de época; checkpoints reseteados.
- ed25519 strict-profile: convenciones de retorno de libsodium correctas; ningún camino de éxito
  salta una comprobación; 150/150 Wycheproof + KATs RFC 8032 + casos de torsión/identidad rechazan
  correctamente.
- Poseidon: módulo BN254-Fr, constantes de ronda y MDS consistentes; reproduce el valor de interop de
  circomlib/go-iden3; padding del sponge re-derivado independientemente.
- SHA3 (padding 0x06) vs Keccak (0x01): cada uno con su padding y cableado al opcode correcto.
- Blake2b/BLAKE3: reproducen vectores externos; build SIMD-disabled reproducible activo de hecho.
- Claves PQ **sí** se cifran en wallet cifrada (`AddKeyPubKey`/`DecryptKey` validan
  `ML_DSA_44_KEYDATA_SIZE`). No hay hueco de PQ sin cifrar.
- `getaddressdeltas` con `assetName=="*"`: solo amplía el alcance de asset; no filtra datos de otras
  direcciones ni bypassa el índice.
- NIP-025 (RBF de AuthScripts de asset): regla de consenso aplicada simétricamente en mempool y
  bloque; el diseño de dos pasadas cierra el bypass vía hijo/paquete.
- NIP-014 (reference inputs v3): gating simétrico ATMP/ConnectBlock; refinputs resueltos solo contra
  el UTXO set de cadena; locking correcto.
- ECIES DePIN: patrón AEAD correcto (tag verificado antes de usar plaintext), nonce de 12 bytes fresco
  por mensaje (sin reuso de IV), clave efímera fresca por mensaje.
- Worker MCP concurrente: estado compartido guardado consistentemente por mutex; `Stop()` hace join en
  orden correcto; colas y caches acotadas; contexto con TTL de evicción.

---

## Prioridad sugerida de remediación

1. **#3** (riesgo destructivo entre redes) y **#5/#6** (puerto DePIN sin auth + UAF): los más
   urgentes por impacto operativo/seguridad inmediato.
2. **#1, #2, #4** (consenso): confirmar intención con el equipo antes de tocar; afectan o pueden
   afectar mainnet.
3. **#7** (colisión de claves PQ): añadir guarda PQ⇒BIP44.
4. Medios (#8–#19) y bajos según capacidad. Dentro de los medios, priorizar #18 (RNG PQ frágil) y
   #19 (firma a ceros vía gateway) por tocar seguridad de claves/integridad de mensajes.

> Nota de confianza: #1, #3 y #5 se confirmaron leyendo el código con las líneas citadas. El resto
> proviene de revisión asistida que reporta haber verificado en el código; los de criptografía se
> validaron además compilando y corriendo vectores. Conviene re-confirmar cada hallazgo de consenso
> contra el código actual antes de aplicar cambios.
