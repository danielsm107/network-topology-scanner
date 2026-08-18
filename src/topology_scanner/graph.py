"""
graph.py
--------
Construye el grafo (networkx) a partir de los resultados del escaneo.
No sabe nada de nmap ni de HTML — solo transforma datos en un grafo.
"""

import networkx as nx


def construir_grafo(resultados: dict, rango: str) -> nx.Graph:
    """
    Construye un grafo simple: un nodo central representa la red escaneada
    y el resto de hosts cuelgan de él (topología en estrella aproximada,
    no la topología física real — para eso haría falta traceroute o SNMP).
    """
    grafo = nx.Graph()

    nodo_red = f"Red {rango}"
    grafo.add_node(nodo_red, tipo="red", titulo=f"Rango escaneado: {rango}")

    for ip, datos in resultados.items():
        etiqueta_puertos = ", ".join(
            f"{p['puerto']}/{p['servicio']}" for p in datos["puertos"]
        ) or "sin puertos abiertos detectados"

        tooltip = (
            f"IP: {ip}\n"
            f"Hostname: {datos['hostname'] or 'N/D'}\n"
            f"MAC: {datos.get('mac') or 'N/D'}\n"
            f"Fabricante: {datos.get('vendor') or 'N/D'}\n"
            f"SO estimado: {datos['so']}\n"
            f"Puertos: {etiqueta_puertos}"
        )

        grafo.add_node(
            ip,
            tipo="host",
            titulo=tooltip,
            hostname=datos["hostname"],
            categoria=datos.get("categoria", "desconocido"),
            num_puertos=len(datos["puertos"]),
        )
        grafo.add_edge(nodo_red, ip)

    return grafo
