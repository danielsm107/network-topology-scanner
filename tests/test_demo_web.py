"""
Tests de scripts/demo_web.py, que abre la interfaz web con un escaneo
inventado ya cargado para hacer las capturas del README. Igual que
demo_arbol.py, no se instala: se carga por ruta. Reutiliza los datos de
demo_arbol.py, así que la comprobación de que todo es inventado ya está en
test_demo_arbol.py.
"""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("streamlit", reason='pip install "topology-scanner[web]" para probar la interfaz web')

CARPETA_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _cargar_demo_web(monkeypatch):
    monkeypatch.syspath_prepend(str(CARPETA_SCRIPTS))   # demo_web importa demo_arbol
    spec = importlib.util.spec_from_file_location("demo_web", CARPETA_SCRIPTS / "demo_web.py")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_el_resultado_de_demo_trae_cambios_respecto_al_escaneo_anterior(monkeypatch):
    resultado = _cargar_demo_web(monkeypatch).resultado_demo()

    assert set(resultado) == {"resultados", "diff", "rango", "rangos", "topologia", "avisos_snmp"}
    diff = resultado["diff"]
    assert diff["primera_vez"] is False
    assert diff["hosts_nuevos"] and diff["hosts_caidos"]
    assert any(c.get("nuevos_sensibles") for c in diff["puertos_cambiados"].values())
    assert set(diff["hosts_nuevos"]) <= set(resultado["resultados"])
    assert not set(diff["hosts_caidos"]) & set(resultado["resultados"])


def test_la_web_de_demo_arranca_con_el_resultado_cargado(monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.syspath_prepend(str(CARPETA_SCRIPTS))
    at = AppTest.from_file(str(CARPETA_SCRIPTS / "demo_web.py"))
    at.run()

    assert not at.exception
    assert [s.value for s in at.main.subheader] == ["Topology", "Inventory", "Changes"]


def test_la_web_de_demo_cambia_a_la_vista_isometrica(monkeypatch):
    """El botón Flat / Isometric junto a "Topology": cambiar de vista solo
    redibuja el panel, no vuelve a escanear (el resultado ya está en
    session_state)."""
    from streamlit.testing.v1 import AppTest

    monkeypatch.syspath_prepend(str(CARPETA_SCRIPTS))
    at = AppTest.from_file(str(CARPETA_SCRIPTS / "demo_web.py"))
    at.run()
    vista = at.main.radio(key="vista_topologia")
    assert vista.options == ["Flat", "Isometric"]
    assert vista.value == "Flat"

    vista.set_value("Isometric").run()

    assert not at.exception
    assert at.session_state["vista_topologia"] == "Isometric"
    assert [s.value for s in at.main.subheader] == ["Topology", "Inventory", "Changes"]


def test_la_web_de_demo_no_usa_la_api_obsoleta_de_componentes(monkeypatch):
    """st.components.v1.html está obsoleto desde Streamlit 1.56 (lo
    sustituye st.iframe) y avisaba de que se eliminaría: sin techo de
    versión en pyproject.toml, una instalación nueva rompería la web."""
    import streamlit.components.v1 as componentes
    from streamlit.testing.v1 import AppTest

    monkeypatch.syspath_prepend(str(CARPETA_SCRIPTS))
    monkeypatch.setattr(componentes, "html", lambda *a, **k: pytest.fail("usa st.components.v1.html"))
    at = AppTest.from_file(str(CARPETA_SCRIPTS / "demo_web.py"))
    at.run()

    assert not at.exception


def test_la_web_de_demo_no_lee_el_historial_real(monkeypatch):
    """El historial.db del directorio de trabajo es el de la red real de
    quien lance la demo: en una captura pública solo pueden salir rangos
    inventados."""
    from streamlit.testing.v1 import AppTest

    monkeypatch.syspath_prepend(str(CARPETA_SCRIPTS))
    monkeypatch.setattr("topology_scanner.webapp.listar_ejecuciones",
                        lambda *a, **k: pytest.fail("la demo ha leído el historial real"))
    at = AppTest.from_file(str(CARPETA_SCRIPTS / "demo_web.py"))
    at.run()

    assert not at.exception
    lista = next(s for s in at.sidebar.selectbox if s.label == "Saved scans")
    assert len(lista.options) == 3
    assert any("2 ranges" in opcion for opcion in lista.options)
