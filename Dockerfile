# Imagen de topology-scanner: CLI (ENTRYPOINT) y web (`topology-scanner-web`).
#
#   docker build -t topology-scanner .
#   docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#       -v "$PWD/datos:/data" topology-scanner 192.0.2.0/24
#   docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#       -e STREAMLIT_SERVER_ADDRESS=127.0.0.1 --entrypoint topology-scanner-web topology-scanner
#   (más en docs/devops/runbooks/01-contenedor.md y compose.yaml)
#
# --network host: con la red puente de Docker, nmap solo vería la red interna
# del contenedor (sin MACs ni fabricantes de la LAN).

# --- Etapa 1: construir el wheel ---------------------------------------------
# Se construye desde el código del repo (no desde PyPI) para que la imagen sea
# exactamente el commit que se construye. setuptools y el código fuente se
# quedan en esta etapa: a la imagen final solo llega el .whl.
FROM python:3.12-slim-trixie AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

# --- Etapa 2: imagen final -----------------------------------------------------
FROM python:3.12-slim-trixie

# nmap + setcap (libcap2-bin). Sin caché de apt para no engordar la capa.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# nmap como usuario no root: en vez de ejecutarlo como root, se le dan al
# binario solo las capacidades de red que usa (sockets raw para ARP/SYN y
# acceso a las interfaces). Solo funcionan si el contenedor las tiene
# (--cap-add / securityContext.capabilities) y sin no-new-privileges /
# allowPrivilegeEscalation: false, que anula las capacidades de archivo.
# NMAP_PRIVILEGED le dice a nmap que use esos privilegios aunque no sea root
# (si no, al ver un usuario normal se limita a un escaneo TCP connect).
# Solo esas dos: el kernel no ejecuta un binario que pida una capacidad que el
# contenedor no tiene, así que una de más (p. ej. net_bind_service) lo rompía
# con --cap-drop ALL o con el drop: [ALL] habitual en Kubernetes.
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap
ENV NMAP_PRIVILEGED=1

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir "$(ls /wheels/*.whl)[web,snmp]" && rm -rf /wheels

# Usuario sin privilegios con UID fijo (los volúmenes de Kubernetes se
# preparan por UID). /data: directorio de trabajo, ahí van historial.db y las
# salidas (HTML, CSV) — en Kubernetes se monta un volumen.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin scanner \
    && install -d -o scanner -g scanner /data
USER scanner
WORKDIR /data

# La web: Streamlit lee su configuración del entorno (lanzar() no acepta
# argumentos). 0.0.0.0 para que se pueda llegar desde fuera del contenedor.
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    PYTHONUNBUFFERED=1
EXPOSE 8501

ENTRYPOINT ["topology-scanner"]
CMD ["--help"]
