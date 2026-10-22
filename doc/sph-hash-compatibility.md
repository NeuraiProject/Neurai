# Compatibilidad de hashes SPH — 2026-10-22

Corregidos los accesos desalineados y los desplazamientos de negativos detectados
por UBSan durante las pruebas de wallet DePIN. Los resultados comprobados se
conservan byte por byte, incluido el hash X16R del génesis de mainnet. Entrega
sobre `10675d82c90ae641be26e086940535aad300ccdb`, sin nuevo commit ni despliegue.

## Cambios

- `src/algo/sph_types.h` y su copia idéntica `src/crypto/sph_types.h` cargan y
  guardan representaciones de enteros mediante `memcpy`. Se conservan los swaps,
  las ramas de endian y los fallbacks por bytes. Esto elimina desreferencias de
  punteros convertidos con alineación o tipo efectivo incompatibles, también en
  los helpers `_aligned`; los tamaños y bytes de salida no cambian.
- `src/algo/simd.c` sustituye los 14 desplazamientos de valores potencialmente
  negativos de FFT16 por multiplicaciones acotadas. Las cotas de FFT8 dan
  `|d2_i * 2^i| <= 554496`, dentro de `s32`. REDS1/REDS2 expresan el antiguo
  desplazamiento aritmético a la derecha con división que redondea hacia menos
  infinito, sin negar el mínimo entero. Las máscaras se aplican a valores sin
  signo. No se depende del desplazamiento de un negativo de C.
- Las fixtures de `depin_sections_wallet_tests` y
  `depin_selfrevoke_wallet_tests` seleccionan explícitamente la ruta SHA256d de
  testnet antes de construir `TestingSetup`, y restauran las banderas de red y
  la activación KAWPOW al destruirse. `SelectParams` por sí solo deja
  intencionadamente esas banderas intactas en las pruebas. Se comprueba el
  génesis fijo de testnet y la restauración de ámbitos anidados. No cambia la
  selección de red de producción ni la activación de algoritmos.

Los formatos DePIN, firmas, claves, RPC y persistencia no cambian con esta
corrección. El código KAWPOW y sus parámetros tampoco cambian.

## Referencia independiente

Se utilizó la implementación **Java** del autor de SPH,
[sphlib](https://github.com/pornin/sphlib), fijada al commit
`15b6b8d8f3e4a43c58ba102d712fa6b8a3317035`. El código Java no comparte los
helpers C que se corrigen. La versión original del C/C++ del nodo se compiló y
comparó con Java antes de copiar la corrección al entorno remoto. Los valores
esperados se congelaron desde Java, no desde el C corregido.

El corpus reproducible contiene **4516 casos**: los 16 componentes de X16,
longitudes de borde y mensajes aleatorios, SIMD/Fugue largos, todos los
selectores de X16R/X16RV2, composiciones mixtas y el encabezado histórico del
génesis. Se conservan 50 casos de Java en `src/test/data/sph_compat.json` para la
suite habitual. El hash X16R de mainnet comprobado es
`00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806`.

La adaptación Java reproduce la composición X16 y el relleno con ceros tras
Tiger en X16RV2; sus componentes criptográficos son independientes. Los
vectores publicados de bit-longitud de sphlib proporcionan una segunda
comprobación para las variantes SIMD/Fugue de 224, 256, 384 y 512 bits.

## Validación en Docker remoto

Todas las ejecuciones de comparación y pruebas se hicieron en `dev128`, en el
contenedor privado `depin-p9p1p3-20261021`, con red `none`, todas las capacidades
retiradas, `no-new-privileges`, 8 CPU y 16 GiB. Se reutilizaron fuentes y
compilaciones de diagnóstico separadas; las cadenas y wallets son desechables.
No se utilizó una wallet ni cadena de producción.

| Comprobación | Resultado |
|---|---|
| C/C++ original GCC `-O2` frente a Java | 4516/4516 idénticos |
| Corregido GCC `-O0`, `-O2`, `-O3` | 4516/4516 idénticos en cada configuración |
| GCC portátil, `SPH_UNALIGNED=0`, `SPH_NO_ASM=1` | 4516/4516 idénticos |
| GCC y Clang ASan/UBSan `-O1` | 4516/4516 idénticos, sin diagnósticos |
| Clang `-O2` y `-O3` | 4516/4516 idénticos en cada configuración |
| Ejecutable ARM64 GCC `-O2` bajo QEMU | 4516/4516 idénticos |
| Helper `test_neurai_hash` del build normal | 354/354 encabezados X16R/X16RV2 coinciden con Java |
| Vectores publicados SIMD/Fugue, GCC, Clang y GCC ASan/UBSan | 16384 por configuración, aprobados; también pasan los tests de tipos de sphlib |
| Orden de bytes, offsets 0–15 y canarios, ambas copias de `sph_types.h` | 20800 comprobaciones por ejecución; 10 ejecuciones GCC, sanitizadores GCC/Clang y ARM64 normal/portátil aprobadas |
| Nuevas pruebas unitarias `sph_tests` | 3 casos / 30476 aserciones aprobados |
| Suite completa normal, `DEBUG_LOCKORDER` | **1462 casos / 6688137 aserciones aprobados** |
| Selección conjunta SPH, hash, criptografía y DePIN con ASan/UBSan | **160 casos / 233291 aserciones aprobados**, incluidos los 13 casos de las dos fixtures de wallet |
| Regtest `feature_depin_pool_state.py` | Aprobado: cursores, moderación, almacenamiento, caída abrupta y reinicios |
| Regtest `feature_depin_messaging_permissions.py` | Aprobado: permisos, reorganizaciones y concurrencia |

GCC 12.2, Clang 14, Java 17 y QEMU 7.2; las versiones completas, dependencias y
hashes figuran en las evidencias. Los paquetes de Clang, Java y cross-compilación
se prepararon mediante repositorios Debian firmados y se instalaron dentro de
este contenedor. No se habilitó su red ni se ampliaron capacidades. Se conserva
el manifiesto SHA-256 de esos paquetes.

Los dos fallos originales se reproducen separadamente con las fuentes previas:
una escritura de 32 bits en un offset desalineado y el desplazamiento de un
negativo de SIMD con una entrada no nula. Las ejecuciones finales usan
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, sin excluir SPH ni desactivar
el diagnóstico de desplazamiento o alineación.

Una ejecución inicial de los tests publicados encontró además
`memcpy(dst, NULL, 0)` en el **harness externo** para su vector vacío. El runner
copia ese harness y condiciona únicamente esa llamada a longitud distinta de
cero. Los vectores y el código del algoritmo permanecen intactos; no se suprime
la comprobación UBSan. También se conservan los intentos de enlace del runner
`-O0`: se resolvieron eliminando secciones no utilizadas de Ethash, sin stubs.

## Rendimiento y límites

Once rondas alternas de los binarios original/corregido GCC `-O2`, fijadas a una
CPU y después de terminar las demás pruebas, conservan los mismos guards de
salida. Las medianas de SIMD/Fugue varían entre **−1,59 % y +0,94 %**; X16R,
**+5,35 %** y X16RV2, **+0,41 %**. Los hashes X16 se midieron en lotes cortos de
1000 iteraciones en un host compartido. Estos datos se registran como
microbenchmark diagnóstico y no acreditan el rendimiento de un minero real.

Las herramientas y los comandos están en
[contrib/devtools/sph](../contrib/devtools/sph/README.md). La instrumentación del
runner independiente incluye todos los componentes SPH y Tiger. La compilación
del nodo con sanitizadores conserva las limitaciones ya registradas: secp256k1
portátil, ensamblador manual SHA256 sin instrumentar, dependencias estáticas de
la imagen sin certificación y LeakSanitizer desactivado. El enlace sin PIE y
`ASAN_OPTIONS=handle_segv=0:detect_leaks=0` evitan el problema de arranque del
manejador ASan observado en este entorno. No se declara instrumentado todo el
nodo ni aprobada toda su suite con sanitizadores.

ARM64 se comprobó mediante emulación del ejecutable de hashes; no se compiló
un nodo ARM64 completo ni se probó hardware ARM físico o una máquina big-endian.
Se verificó el génesis histórico y las suites existentes de KAWPOW y encabezados,
pero **no se reprodujo la cadena histórica completa**. El corpus y los
sanitizadores aportan evidencia y regresiones reproducibles, no una prueba
exhaustiva de todas las entradas posibles.

El hallazgo **F-SAN-1** del plan DePIN queda cerrado en este alcance. Las tareas
P2, P7 y la adaptación posterior de librerías externas mantienen su seguimiento
independiente.
