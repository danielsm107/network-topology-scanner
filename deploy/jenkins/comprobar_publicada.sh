#!/bin/sh
# ¿Está publicada esta versión? comprobar_publicada.sh <X.Y.Z>
# El tag aparece antes que la imagen, y si los tests fallan la imagen no llega
# nunca. La señal es la release de GitHub, que release.yml crea la última, y
# además el tag en GHCR. Código 0 = publicada; 1 = todavía no, también ante
# cualquier error de red o límite de peticiones: quien llama vuelve a preguntar.
set -u

version="$1"
REPO_GITHUB="${REPO_GITHUB:-danielsm107/network-topology-scanner}"
IMAGEN_GHCR="${IMAGEN_GHCR:-danielsm107/topology-scanner}"

codigo=$(curl -s -m 30 -o /dev/null -w '%{http_code}' \
  "https://api.github.com/repos/$REPO_GITHUB/releases/tags/v$version") || exit 1
[ "$codigo" = "200" ] || exit 1

token=$(curl -s -m 30 "https://ghcr.io/token?scope=repository:$IMAGEN_GHCR:pull" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || exit 1

codigo=$(curl -s -m 30 -o /dev/null -w '%{http_code}' --head \
  -H "Authorization: Bearer $token" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
  "https://ghcr.io/v2/$IMAGEN_GHCR/manifests/$version") || exit 1
[ "$codigo" = "200" ]
