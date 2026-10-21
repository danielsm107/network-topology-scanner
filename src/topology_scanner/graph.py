"""
graph.py
--------
Construye el grafo (networkx) a partir de los resultados del escaneo.
No sabe nada de nmap ni de HTML — solo transforma datos en un grafo.

Dos modos:
- Sin topología: estrella aproximada (nodo central = red, hosts colgando).
- Con topología (lo que devuelve snmp.inferir_topologia): árbol real de
  equipos de red, con cada host colgando de su router/AP. graph.py no sabe
  nada de SNMP, solo del formato de ese dict.

Cada nodo que no es el central lleva `padre` (el nodo del que cuelga, None
en las raíces) para que el layout pueda dibujarlo por niveles.

`rango` puede ser un texto (un rango) o una lista (varios, ver rangos.py):
en la estrella hay un nodo central por rango, y cada host cuelga del suyo.
"""

import ipaddress

import networkx as nx

from .rangos import rango_de


def construir_grafo(resultados: dict, rango: str | list[str], topologia: dict | None = None) -> nx.Graph:
    rangos = [rango] if isinstance(rango, str) else list(rango)
    if topologia is None:
        return _grafo_estrella(resultados, rangos)
    return _grafo_topologia(resultados, rangos, topologia)


def _grafo_estrella(resultados: dict, rangos: list[str]) -> nx.Graph:
    """
    Construye un grafo simple: un nodo central por rango escaneado y los
    hosts colgando del suyo (topología en estrella aproximada, no la
    topología física real — para eso está el modo con topología).
    """
    grafo = nx.Graph()

    for rango in rangos:
        grafo.add_node(_nodo_red(rango), tipo="red", rango=rango, titulo=f"Rango escaneado: {rango}")

    for ip, datos in resultados.items():
        nodo_red = _nodo_red(rango_de(ip, rangos))
        grafo.add_node(ip, **_atributos_host(ip, datos), padre=nodo_red)
        grafo.add_edge(nodo_red, ip)

    return grafo


def _nodo_red(rango: str) -> str:
    return f"Red {rango}"


def _atributos_host(ip: str, datos: dict) -> dict:
    etiqueta_puertos = ", ".join(
        f"{p['puerto']}/{p['servicio']}" for p in datos["puertos"]
    ) or "sin puertos abiertos detectados"

    alertas = datos.get("alertas", [])

    tooltip = (
        f"IP: {ip}\n"
        f"Hostname: {datos['hostname'] or 'N/D'}\n"
        f"MAC: {datos.get('mac') or 'N/D'}\n"
        f"Fabricante: {datos.get('vendor') or 'N/D'}\n"
        f"SO estimado: {datos['so']}\n"
        f"Puertos: {etiqueta_puertos}"
    )
    if alertas:
        etiqueta_alertas = ", ".join(f"{a['puerto']} ({a['motivo']})" for a in alertas)
        tooltip += f"\n\n⚠ Puertos sensibles abiertos: {etiqueta_alertas}"

    return {
        "tipo": "host",
        "titulo": tooltip,
        "hostname": datos["hostname"],
        "categoria": datos.get("categoria", "desconocido"),
        "num_puertos": len(datos["puertos"]),
        "alertas": alertas,
    }


def _grafo_topologia(resultados: dict, rangos: list[str], topologia: dict) -> nx.Graph:
    grafo = nx.Graph()
    equipos = topologia["equipos"]
    ubicaciones = topologia["ubicaciones"]

    def nombre_de(nodo: str) -> str:
        return equipos.get(nodo, {}).get("nombre") or nodo

    def colgar(nodo: str, padre: str, interfaz: str | None):
        grafo.nodes[nodo]["padre"] = padre
        grafo.add_edge(padre, nodo, interfaz=interfaz)
        donde = f"{nombre_de(padre)} ({interfaz})" if interfaz else nombre_de(padre)
        grafo.nodes[nodo]["titulo"] += f"\nConectado a: {donde}"

    # 1. Equipos de red (con los datos de nmap si también los escaneó)
    for ip, equipo in equipos.items():
        if ip in resultados:
            atributos = _atributos_host(ip, resultados[ip])
            if atributos["categoria"] == "desconocido":
                atributos["categoria"] = "router"
        else:
            atributos = {"titulo": f"IP: {ip}", "hostname": "", "categoria": "router",
                         "num_puertos": 0, "alertas": []}
        atributos["hostname"] = atributos["hostname"] or equipo["nombre"]
        atributos["titulo"] += _descripcion_equipo(equipo)
        # padre=None: si tiene un enlace hacia arriba, colgar() lo rellena después
        atributos.update(tipo="equipo", padre=None, upstream=equipo["upstream"], consultado=equipo["consultado"])
        grafo.add_node(ip, **atributos)

    for enlace in topologia["enlaces"]:
        colgar(enlace["hijo"], enlace["padre"], enlace["interfaz_padre"] or enlace["interfaz_hijo"])

    # 2. Hosts de nmap: por IP, si no por MAC, si no por la red remota a la
    #    que pertenecen; lo que no encaja en nada cuelga del nodo de red.
    ubicacion_por_ip = {u["ip"]: mac for mac, u in ubicaciones.items() if u["ip"]}
    macs_usadas = set()
    for ip, datos in resultados.items():
        if ip in equipos:
            continue
        mac = ubicacion_por_ip.get(ip) or (datos.get("mac") or "").lower()
        grafo.add_node(ip, **_atributos_host(ip, datos))
        if mac in ubicaciones:
            macs_usadas.add(mac)
            colgar(ip, ubicaciones[mac]["padre"], ubicaciones[mac]["interfaz"])
        elif (router := _router_de_red(ip, topologia["redes"])) is not None:
            colgar(ip, router, None)
        else:
            rango = rango_de(ip, rangos)
            nodo_red = _nodo_red(rango)
            if nodo_red not in grafo:
                grafo.add_node(nodo_red, tipo="red", rango=rango, titulo=f"Rango escaneado: {rango}\n"
                               "(hosts sin ubicación en la topología SNMP)")
            colgar(ip, nodo_red, None)

    # 3. Hosts que solo ha visto SNMP (nmap no los detectó o no tienen IP)
    for mac, ubicacion in ubicaciones.items():
        if mac in macs_usadas or ubicacion["ip"] in resultados:
            continue
        nodo = ubicacion["ip"] or mac
        grafo.add_node(
            nodo, tipo="host", hostname="", categoria="desconocido", num_puertos=0, alertas=[],
            solo_snmp=True,
            titulo=(f"IP: {ubicacion['ip'] or 'N/D'}\nMAC: {mac}\n"
                    "Visto por SNMP, no detectado por nmap"),
        )
        colgar(nodo, ubicacion["padre"], ubicacion["interfaz"])

    return grafo


def _descripcion_equipo(equipo: dict) -> str:
    lineas = [f"\n\nEquipo de red: {equipo['nombre'] or 'sin nombre'}"]
    if equipo["plataforma"] or equipo["version"]:
        lineas.append(f"Plataforma: {equipo['plataforma']} {equipo['version']}".rstrip())
    if equipo["consultado"]:
        lineas.append("Consultado por SNMP")
    elif equipo["upstream"]:
        lineas.append("Puerta de enlace (upstream, no consultado por SNMP)")
    return "\n".join(lineas)


def _router_de_red(ip: str, redes: dict) -> str | None:
    """Router que sirve la red más específica que contiene `ip`."""
    try:
        direccion = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    candidatas = [ipaddress.IPv4Network(red) for red in redes if direccion in ipaddress.IPv4Network(red)]
    if not candidatas:
        return None
    return redes[str(max(candidatas, key=lambda red: red.prefixlen))]
