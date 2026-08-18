"""
Test de topology_scanner/__init__.py: la versión se lee del paquete
instalado (importlib.metadata), no de una copia a mano que podía
desincronizarse de la de pyproject.toml.
"""

import re

from topology_scanner import __version__


def test_version_se_lee_del_paquete_instalado():
    assert re.match(r"^\d+\.\d+\.\d+", __version__)
