"""topology_scanner — escáner de topología de red con nmap + networkx + pyvis."""

from importlib.metadata import PackageNotFoundError, version

try:
    # pyproject.toml es la única fuente de verdad para la versión - antes
    # había una copia a mano aquí que podía desincronizarse.
    __version__ = version("topology-scanner")
except PackageNotFoundError:
    # Código fuente sin instalar (ni siquiera "pip install -e .")
    __version__ = "0+unknown"
