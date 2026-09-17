# Revisión de la implementación local de AuthScript estricto

## Seguimiento tras las correcciones

Repetidos de forma independiente en Docker los tests específicos de revisión:

- `strict_authscript_tests`: 13 casos y 182 aserciones correctas.
- `strict-authscript-recovery-review.py`: 7 comprobaciones correctas.

Los cuatro fallos reproducidos originalmente (activación de activos en
`CheckTransaction`, restauración PQ, importación de claves y separación de firmas
de mensaje) ya no se reproducen en esos casos. Se revisaron las correcciones:
parser de activos condicionado por red, registro de destinos estrictos en
generación/importación y carga de wallet PQ, y hash de mensaje vinculado a
versión y compromiso. Esto valida esas regresiones, no toda la activación futura.

El cambio de ruta de la identidad DePIN en mainnet queda confirmado por el
responsable del proyecto como intencional: DePIN usa coin type 1900. El 0 fue
una elección inicial errónea y se mantiene en la derivación histórica del nodo
por compatibilidad con wallets existentes de exchanges y mineros. Según la
aclaración del responsable, las wallets software usan 1900 por defecto y ofrecen
un selector para recuperar las antiguas con 0. Esta decisión cierra el hallazgo
de compatibilidad DePIN; no autoriza cambiar la derivación Legacy del nodo ni
implica que ambas rutas produzcan la misma clave.

La ejecución global de 1069 casos (excluyendo dos tests de génesis de testnet)
y las 92 comprobaciones del guion de tres nodos fueron comunicadas por el autor
de las correcciones; no se repitieron en este seguimiento. Permanecen pendientes
el selector de covenants, dust v1, vectores fijos y activación con reorganización
y calendario público. No presentar esta entrega como el plan completo ni como
lista para activar en redes públicas.

Las secciones siguientes conservan la revisión inicial y sus resultados como
historial; los fallos indicados en ellas no describen el resultado de la repetición
anterior.

## Hallazgos

### P1 — La desactivación de activos v2/v3 no protege el validador de transacciones

`src/script/script.cpp`, `CScript::IsAssetScript`, reconoce OP_2/OP_3 sin comprobar
la activación. `CheckTransaction` y `Consensus::CheckTxAssets`, en
`src/consensus/tx_verify.cpp`, solo recurren a `CheckXnaAssetOutputPlacement`
cuando el script no ha sido reconocido como activo. Por tanto, el control nuevo
de `nStrictAuthScriptEnabled` en `HasAssetOpcodeInExpectedPosition` no cubre los
scripts válidos de activos estrictos.

Reproducción: `review_strict_assets_rejected_before_activation` construye
transferencias con versiones 2 y 3 y ejecuta `CheckTransaction` bajo mainnet y
testnet. Las cuatro son aceptadas con `nStrictAuthScriptEnabled = false`.
Antes del cambio, el parser no reconocía esos prefijos y se rechazaban por
posición incorrecta de OP_XNA_ASSET.

Esto demuestra una diferencia en validación antes de activar, no una transacción
publicada ni una prueba de bloque completo. Revisar también los metadatos de
activos nulos/restringidos, cuya detección se amplió sin una condición equivalente.

Corrección: aplicar las reglas de activación en los puntos de consenso que
admiten las salidas, incluidos los caminos de activos válidos. Probar ambas
validaciones, bloques, mempool y metadatos; no basta con probar el helper aislado
ni con bloquear la decodificación de direcciones.

### P1 — Restaurar la semilla PQ no descubre los pagos estrictos

`src/wallet/wallet.cpp`, `GenerateNewKeyPQ`, registra únicamente el destino
genérico mediante `GetDefaultAuthScriptDestination`. El destino estricto se
registra cuando se solicita explícitamente o se utiliza para cambio. En una
wallet restaurada, `IsMine` exige datos de gasto versionados que no existen.

Reproducción en nodos nuevos de regtest, con las mismas palabras públicas de
prueba: un pago de 5 XNA a v2 no aparece como gastable en `listunspent` y
`validateaddress.ismine` es false. Un control comprueba que la clave privada
correspondiente sí está en la wallet restaurada. El pago equivalente v3 se
recupera correctamente.

Corrección: registrar/descubrir los destinos estrictos PQ al regenerar las claves,
antes del escaneo, y cubrir recepción/cambio, avance del keypool y recuperación
desde una copia anterior a la emisión de direcciones. No depender de que el
usuario vuelva a pedir manualmente las mismas direcciones.

### P1 — Exportar/importar la clave no recupera el destino estricto

`src/wallet/rpcdump.cpp`, `importprivkey`, registra v1 para PQ o el destino Legacy
para ECDSA. No registra los datos de gasto v2/v3. La ruta compartida
`AddKeyPubKeyWithDB` tampoco los incorpora.

Reproducción: `dumpprivkey` de un destino estricto, seguido de `importprivkey`
en otra wallet, termina sin error, pero `validateaddress` no reconoce como propio
el destino original. Ocurre tanto con PQ como con ECDSA.

Corrección: hacer explícita la recuperación de las plantillas estrictas al
importar claves. Cubrir también `dumpwallet`/`importwallet`, importación repetida
de claves ya conocidas, rescan y firma posterior. No confundir recuperar una
clave con recuperar sus destinos y condiciones de gasto.

### P2 — Las firmas de mensaje no quedan vinculadas a la versión del destino

`src/base58.cpp`, `SignMessageHash` y `VerifyMessageHash`, utilizan el mismo hash
de mensaje para los destinos antiguos y estrictos. La verificación reconstruye
la dirección desde la clave, pero eso no prueba para cuál de sus direcciones
firmó el usuario.

Reproducción: `review_message_signature_bound_to_destination_version` usa una
misma clave bajo ambos formatos. Una firma PQ v1 verifica como v2 y viceversa;
una firma Legacy ECDSA verifica como v3 y viceversa. Las cuatro comprobaciones
negativas fallan. El test anterior usaba claves/algoritmos diferentes y no cubría
este caso.

Corrección: definir y probar un dominio de mensaje para las familias nuevas que
vincule versión/destino, conservando la verificación histórica. Este hallazgo
afecta a firmas de mensajes; no demuestra replay de firmas de transacciones,
cuyo sighash estricto sí se modificó.

### Cerrado por decisión del proyecto — Identidad DePIN en mainnet

`src/wallet/depinpoolkeyload.cpp`, `DeriveDepinPoolKeys`, sustituye el coin type
histórico por 1900 en mainnet. Para la misma semilla cambia la ruta de
`m/44'/0'/200'/0/0` a `m/44'/1900'/200'/0/0` y, por tanto, la clave del servicio.
Se aplica aunque las familias estrictas estén desactivadas.

El responsable del proyecto confirma que este cambio es intencional: DePIN
adopta 1900, mientras que el nodo conserva 0 exclusivamente en la derivación
Legacy histórica para no alterar la recuperación de fondos existentes. No se
requiere revertir ni separar este cambio como condición de esta revisión.
Las identidades calculadas con las dos rutas son distintas; no se afirma una
migración automática. Hallazgo cerrado por decisión de diseño, no por una
prueba con identidades reales.

## Tests ejecutados y cambios de esta revisión

Docker: `neurai-strict`, binarios bajo `/root/Neurai/src`. Se contrastaron los
archivos de producción de wallet, base58 y tx_verify con los del workspace.

- Suite original `strict_authscript_tests`: 11 casos, 162 aserciones correctas.
- Añadidos dos casos en `src/test/strict_authscript_tests.cpp`: resultado conjunto
  11 casos correctos y 2 fallidos; 174 aserciones correctas y 8 fallidas.
- Añadido `scripts/strict-authscript-recovery-review.py`: 3 comprobaciones
  correctas y 4 fallidas. Usa nodos y wallets temporales, una semilla pública de
  prueba y conexiones loopback; cierra sus nodos y devuelve error ante fallos.
- Corregida la salida de `scripts/strict-authscript-regtest.sh`: anteriormente
  el último `echo` devolvía éxito incluso cuando FAIL era mayor que cero. Ahora
  devuelve error cuando su contador registra fallos. Se validó la sintaxis;
  no se repitió aquí todo ese script.

Los tests de regresión quedan deliberadamente fallando hasta corregir los
hallazgos. No se ejecutó toda la suite global, la GUI ni pruebas públicas.

Comandos dentro del contenedor, tras compilar el test actualizado:

```sh
cd /root/Neurai
src/test/test_neurai --run_test=strict_authscript_tests --report_level=short --log_level=error
python3 /src/scripts/strict-authscript-recovery-review.py --bindir /root/Neurai/src
```

Logs de esta revisión en el host: `/tmp/neurai-strict-review/unit.log` y
`/tmp/neurai-strict-review/recovery.log`.

## Cobertura y alcance pendientes

- El selector nuevo de 33 bytes para covenants no aparece en el diff. Los
  selectores antiguos permanecen v1, lo cual conserva su comportamiento, pero
  no completa esa parte del plan.
- El fallo anterior de dust v1 sigue presente; las estimaciones nuevas v2/v3 no
  corrigen ese problema. Tratarlo como corrección independiente.
- Añadir vectores conocidos de commitment, dirección y sighash. Los tests
  actuales calculan varios valores con las mismas funciones que luego verifican;
  no detectan todos los cambios accidentales compatibles entre firmador y verificador.
- Probar reservas de cambio con activos y sin cambio monetario, keypools
  agotados, backups anteriores al uso de las direcciones e importación de wallet.
- Probar activación/reorganización en bloques completos. Los cambios actuales
  usan un booleano por red y solo activan las familias en regtest; todavía no
  implementan un calendario de activación pública.

Prioridad de la revisión inicial: corregir el aislamiento de consenso, la
recuperación de fondos y la semántica de firmas de mensaje, y aclarar la
derivación DePIN. Véase el seguimiento al inicio: las regresiones específicas
ya pasan y la decisión DePIN ha sido confirmada.
