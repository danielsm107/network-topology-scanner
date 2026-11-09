#!/bin/sh
# Decide qué versión desplegar. Lee por stdin los tags del repo, uno por línea.
#   elegir_version.sh <versión desplegada> <archivo de versiones fallidas>
# Imprime X.Y.Z, o nada si no hay nada que desplegar. Solo tags vX.Y.Z exactos,
# nunca hacia atrás, y nunca una versión marcada como fallida.
# Sin saber qué hay desplegado o qué falló, se para (código 2): seguir como si
# no hubiera nada reabriría el bucle de reintentos.
set -eu

desplegada="${1:-}"
fallidas="${2:-}"
if [ -z "$desplegada" ] || [ ! -f "$fallidas" ]; then
  echo "ERROR: hacen falta la versión desplegada y el archivo de fallidas" >&2
  exit 2
fi

# Las fallidas en BEGIN: el truco NR == FNR no funciona con un archivo vacío
candidata=$(
  grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' \
    | awk -v archivo="$fallidas" '
        BEGIN { while ((getline linea < archivo) > 0) fallida[linea] = 1 }
        !($0 in fallida)' \
    | sort -V | tail -n 1
)
[ -n "$candidata" ] || exit 0

mayor=$(printf '%s\n%s\n' "$desplegada" "$candidata" | sort -V | tail -n 1)
if [ "$mayor" = "$candidata" ] && [ "$candidata" != "$desplegada" ]; then
  echo "$candidata"
fi
