# Revisión de activación por altura

Estado revisado: cambios sin commit sobre `8afe663` (dust v1), aunque la petición
los describía como un commit. No se ha modificado código de producción.

Resultado actualizado: las reproducciones originales y la variante P2SH ya
pasan con las correcciones actuales. No se han encontrado nuevos defectos en
la revisión del arreglo P2SH. Las secciones de diagnóstico de abajo conservan
el historial de los fallos, no describen defectos todavía pendientes.

## Verificación del arreglo P2SH

`SpendsStrictAuthScriptProgram` inspecciona ahora el redeemScript revelado por
el scriptSig cuando la moneda es P2SH. Para un programa estricto válido de 34
bytes, la extracción mediante GetOp obtiene el mismo programa que reconoce el
intérprete; las entradas del mempool ya han superado la verificación del hash
y de la forma del scriptSig. El predicado se usa en ambas pasadas del barrido.

Se repitieron el reproductor nativo y el P2SH sobre el binario del contenedor,
con validation.cpp coincidente con el workspace: ambos pasan (exit 0).
Además se amplió el reproductor P2SH con un descendiente que gasta una salida
Legacy: también se retira al cruzar bajo la altura (exit 0). Esto comprueba
que la retirada recursiva funciona aunque el hijo no sea un gasto estricto.

No se repitió en esta revisión la prueba de 34 comprobaciones ni la suite
completa. Sus resultados comunicados por el autor son evidencia separada.
No se ha cambiado código de producción ni hecho commit. Permanecen pendientes
las pruebas de integración enumeradas más abajo.

## Seguimiento de las correcciones

- Suite `strict_authscript_tests`: 17 casos y 227 aserciones correctas, ejecutados
  de nuevo en `neurai-strict`. Se comprobó que interpreter.cpp, validation.cpp y
  el archivo de tests coinciden entre el workspace y la copia de compilación.
- El reproductor original de mempool pasa: gasto nativo v3 retirado al retroceder
  de punta 119 a 118, con activación 120 y financiación confirmada en 118.
- El contexto de flags ahora abarca EvalScript, VerifyScript y CountWitnessSigOps;
  corrige el camino ambiental de introspección comprobado por el test original.
- FillBlock establece ahora el contexto del padre antes de CheckBlock. Revisado
  en código; no se ha ejecutado una prueba específica de bloques compactos.
- No se repitieron ni interrumpieron las regresiones completas del autor.

### P2 corregido — Diagnóstico histórico de la omisión P2SH

En `src/validation.cpp`, `MempoolEvictStrictAuthScriptEntries` consulta solamente
el scriptPubKey de la moneda gastada mediante `IsStrictAuthScriptProgram`.
Para P2SH ese script es HASH160/EQUAL: el programa v2/v3 está en el redeemScript
revelado por el scriptSig. VerifyScript e IsWitnessStandard sí reconocen esta
forma, pero el barrido no la desempaqueta.

Reproductor persistente: `scripts/strict-authscript-p2sh-activation-review.py`.
Confirma financiación P2SH-v3 en 118, admite su gasto en punta 119 y después
invalida 119. El gasto sigue en mempool en punta 118. Resultado observado:
`FAIL: unconfirmed P2SH strict spend remains in mempool below activation`
(exit 1). Son nodos desechables y una firma válida; no se omite la verificación.

Corrección propuesta: cuando la moneda gastada sea P2SH, inspeccionar también
el redeemScript del scriptSig y detectar allí los programas estrictos v2/v3,
retirando el gasto y sus descendientes. Añadir regresión para esta forma en los
cruces de activación. La segunda pasada al terminar la reorganización no corrige
esta omisión porque usa el mismo predicado.

El caso demuestra una inconsistencia de política, no un bloque inválido en
consenso: bajo activación las versiones desconocidas siguen siendo permisivas.

Siguen siendo útiles las pruebas de bloque completo con y sin workers y el
rechazo de salidas de activos estrictas por debajo de activación. El scope de
flags justifica el arreglo, pero no sustituye esas pruebas de integración.

## P1 — La introspección de activos aún depende del contexto ambiental

`VerifyScript` y `CountWitnessSigOps` pasan la activación explícita al reconocer
la entrada de activo, pero no todas las consultas ejecutadas por un script lo
hacen. `TransactionSignatureChecker::GetOutputAssetField`, `GetInputAssetField`
y `GetRefInputAssetField` llaman a `TransferAssetFromScript` y otros parsers que
consultan el contexto ambiental.

Reproducción añadida a `src/test/strict_authscript_tests.cpp`:
`review_asset_introspection_uses_script_flags`. Un covenant v1 con autenticación
tipo 0 comprueba mediante `OP_OUTPUTASSETFIELD` el nombre de un activo pagado a
una salida v3. Con los mismos flags, que incluyen activación estricta, la
verificación pasa con contexto ambiental activo y falla con contexto inactivo.
Resultado: una aserción correcta y una fallida.

La prueba reproduce directamente la dependencia mediante `VerifyScript`; no es
una demostración de división de cadena ni una ejecución de bloque completo con
workers. Sí contradice la garantía de que el intérprete obtiene toda la
activación de los flags. Un hilo worker no hereda el scope del hilo llamador y
recurrirá al valor por defecto en estas consultas.

Corrección propuesta: transmitir el contexto explícito también a las consultas
de campos de activos, o establecer de forma segura el contexto de flags durante
toda la ejecución correspondiente en el hilo verificador. Cubrir salidas,
entradas gastadas y referencias, con contexto ambiental opuesto, y después
comparar validación síncrona y workers. No cambiar los opcodes v1 de commitment.

## P2 — La transición no limpia todos los gastos estrictos pendientes

`MempoolRemoveForNewTip` recibe el contexto nuevo, pero delega en
`CTxMemPool::removeForNewTip`, que omite entradas sin `GetUsesChainContext()`.
Los gastos estrictos ordinarios no ejecutan `OP_CHAINCONTEXT` y quedan fuera.
Además, esa ruta está condicionada a `nCHAINCONTEXTEnabled` y solo revalida
scripts: no basta para salidas nuevas de activos cuya admisibilidad cambie.

Reproducción en regtest con nodos nuevos, activación 120:

1. Confirmar en 118 una salida nativa v3 (no activo), aún permisiva en consenso.
2. Llegar a 119 y admitir un gasto v3 de esa salida en mempool, sin minarlo.
3. Invalidar el bloque 119. La salida gastada sigue confirmada en 118.
4. El gasto continúa en mempool, aunque una nueva admisión bajo esas reglas
   debería rechazarlo por witness desconocido desalentado.

Resultado del reproductor: `FAIL: unconfirmed strict spend remains in mempool
below activation`. Es inconsistencia de política para este caso de monedas,
no prueba de un gasto inválido en consenso: las reglas antiguas son permisivas.

La prueba de 32 comprobaciones retira y readmite transacciones de bloques
desconectados; no cubre esta población que ya estaba pendiente.

Corrección propuesta: tratar el cruce de activación como transición propia,
independiente de OP_CHAINCONTEXT, y revalidar/retirar las entradas afectadas y
descendientes. Añadir también pagos a activos v2/v3 con entradas Legacy/v1:
en ese caso debe comprobarse la salida, no solo las firmas de las entradas.

## Alcance y evidencias

- El test nuevo se compiló y enlazó como ejecutable independiente
  `/tmp/test_neurai_activation_review` en `neurai-strict`, sin sustituir el
  ejecutable de las suites en curso.
- Resultado del test: `/tmp/activation-review-result.log` en el contenedor.
- Reproductor mempool: `/tmp/strict-activation-mempool-review.py` en host y
  contenedor. Usa wallets desechables y conexiones locales. Resultado en
  `/tmp/activation-review-mempool.log` dentro del contenedor.
- Las suites completas del autor no se interrumpieron ni se repitieron.
- No se modificó la implementación ni se hizo commit. El test nuevo queda
  fallando deliberadamente hasta corregir la dependencia del contexto.

Antes de cerrar esta entrega, ampliar la prueba de altura con activos,
covenants de introspección, transacciones ya pendientes y sus descendientes.
Revisar también las llamadas a `CheckBlock` desde reconstrucción de bloques
compactos: `PartiallyDownloadedBlock::FillBlock` no establece el scope nuevo.
Esta última observación es cobertura pendiente, no un tercer fallo reproducido.
