# Fase 6: observabilidad, diseño

Continúa [`2026-10-22-fase-devops-design.md`](2026-10-22-fase-devops-design.md),
que ya fijaba las piezas (Prometheus, Alertmanager → Telegram, Grafana,
kube-state-metrics) y dejaba abierto cómo sacar las métricas del escaneo.

## Intención

Hoy, si algo del homelab se rompe, el mantenedor se entera tarde o por
casualidad. El fallo real que ha tenido es **un corte de luz**: se apaga el
MiniPC entero (Proxmox, la VM k3s y todo lo que corre dentro). Ningún sistema
de alertas que viva dentro de esa máquina puede avisar de que esa máquina está
apagada. Por eso el diseño tiene dos mitades:

1. **Desde dentro**: Prometheus vigila lo que pasa con el clúster encendido
   (Jobs que fallan, el nocturno que no corre, disco lleno, pods que no
   arrancan) y avisa por Telegram.
2. **Desde fuera**: un "interruptor de hombre muerto". El clúster da señales
   de vida a un servicio externo cada pocos minutos; si dejan de llegar, es el
   servicio externo quien avisa. Así un corte de luz también llega a Telegram,
   y cuando vuelve la luz, otro aviso dice que ha vuelto y cuánto estuvo caído.

Para el portfolio, esto responde a "¿cómo sabes que tu sistema funciona?" y a
"¿y si se cae la máquina que te tiene que avisar?", que es la pregunta que
separa una instalación de Grafana de un sistema de alertas pensado.

## Objetivos

1. Prometheus, Alertmanager, Grafana, kube-state-metrics y node-exporter en
   k3s, en el namespace `monitoring`, instalados con Helm y configurados como
   código (reglas, paneles y rutas de alerta en el repo).
2. Avisos por **Telegram** de lo que pasa con el clúster encendido.
3. **Corte de luz o caída de la máquina** avisado por Telegram desde fuera, y
   aviso de recuperación al volver.
4. Métricas del escaneo nocturno (hosts vivos, puertos sensibles, hosts nunca
   vistos, duración) con su panel en Grafana, con histórico.
5. Todo **ensayado de verdad**: un Job que falla a propósito, la VM apagada a
   mano, un reinicio.
6. Documentación: runbook `06-observabilidad.md`, `decisiones.md`, README de
   DevOps (fase 6 Hecha) y `CLAUDE.md`.

## No-objetivos

- **Evitar el apagón.** Eso es hardware (un SAI y NUT para apagar ordenado);
  queda como idea. Esta fase solo hace que el apagón **se sepa**.
- Logs centralizados (Loki) y trazas.
- Grafana fuera de la LAN: mismo patrón que la web y Jenkins (NPM con Access
  List solo LAN).
- Métricas de Jenkins y de las LXC de Proxmox que no son k3s.
- Alta disponibilidad de la monitorización: un nodo, aceptado.

## Anti-objetivos (fracaso aunque "funcione")

- **Avisos que se acaban ignorando.** Es lo que pasó con el email nocturno
  hasta la 1.5.0. Cada regla tiene que indicar algo que el mantenedor querría
  arreglar; nada que salte a diario por estado normal. Las reglas por defecto
  del chart que en k3s dan falsos positivos (componentes del plano de control
  que k3s no expone por separado) se desactivan.
- **Dar por cubierto el corte de luz con alertas internas.** Si el ensayo de
  apagar la VM no produce un Telegram, la fase no está hecha.
- **Que la monitorización tumbe lo monitorizado**: límites de memoria y
  retención corta; el nocturno y Jenkins tienen que seguir funcionando igual.
- Secretos (token del bot, URL del servicio externo) en el repo o en el estado.
- Que la app sepa de Prometheus: igual que no sabe de AWS.

## Decisiones

### Instalación

- Chart **`kube-prometheus-stack`** (versión fijada), en `deploy/monitoring/`,
  con `values.yaml` en el repo y un `values.local.yaml` ignorado (dominio).
  Se instala y actualiza **desde el PC**, como el chart de Jenkins: Jenkins
  solo despliega la app.
- Retención de Prometheus corta (15 días) en un PVC de `local-path`; límites de
  memoria en Prometheus y Grafana. Presupuesto: ~1,5 GiB entre todo (el nodo
  usa hoy 2,3 de 8 GiB).
- Desactivado lo que k3s no expone (`kubeControllerManager`, `kubeScheduler`,
  `kubeEtcd`, `kubeProxy`) y sus reglas, para que no haya alertas permanentes.
- Grafana: contraseña de admin desde un Secret creado a mano, sin anónimo,
  paneles como código (ConfigMaps que lee el sidecar del chart), NodePort +
  NPM solo LAN, como Jenkins.

### Avisos desde dentro (Alertmanager → Telegram)

- Receptor `telegram_configs` nativo de Alertmanager. Token del bot y chat ID en
  un Secret creado a mano desde un archivo en `~/.config/topology-scanner/`
  (mismo patrón que SNMP y AWS); el repo solo lo referencia.
- Reglas propias, en español, en el repo:
  - El nocturno no ha terminado bien en las últimas ~26 h
    (`kube_cronjob_status_last_successful_time`). Cubre tanto "falló" como "no
    se ejecutó porque la máquina estaba apagada a las 3:00".
  - Un Job del namespace `topology-scanner` ha fallado.
  - Un pod de `topology-scanner`, `jenkins` o `monitoring` no arranca o se
    reinicia en bucle.
  - Un PVC por encima del 85 %.
  - **El nodo se ha reiniciado** (arrancó hace menos de N minutos): aviso
    informativo, que tras un corte de luz confirma que todo ha vuelto solo.
- De las reglas por defecto del chart se conservan las de nodo y Kubernetes que
  tengan sentido en un nodo único; las que no, se desactivan explicando por qué.
- Agrupación y repetición pensadas para no saturar: un mensaje por problema,
  recordatorio cada pocas horas mientras siga, y mensaje de "resuelto".

### Avisos desde fuera (interruptor de hombre muerto)

- Servicio externo: **healthchecks.io**, plan gratuito. Recibe un ping
  periódico; si no llega en el plazo configurado, avisa por su integración de
  Telegram, y avisa otra vez cuando vuelve. Coste cero, sin AWS.
- Quién hace el ping: la alerta `Watchdog` del chart (siempre activa) se envía
  por Alertmanager a la URL de ping con un `webhook_configs` y repetición cada
  pocos minutos. Así el ping prueba la cadena entera (Prometheus evalúa,
  Alertmanager envía), no solo que la VM tenga red. Si Prometheus o
  Alertmanager se caen, también se avisa.
- Plazo antes de avisar: unos 10-15 minutos, para que un reinicio normal
  (actualizar la VM) no avise.
- La URL de ping es un secreto (quien la tenga puede "dar vida"): va en el
  mismo Secret que Telegram.

### Métricas del escaneo

- La app gana un flag **`--metrics-file RUTA`**: al terminar escribe un archivo
  en el formato de texto de Prometheus. Una función nueva en `export.py`
  (`metricas_prometheus`), sin dependencias nuevas, igual que `--changes-dir`.
  Métricas, por rango: hosts vivos, hosts con puertos abiertos, hosts con
  puertos sensibles, hosts nuevos y nunca vistos del diff, puertos abiertos en
  total; y de la ejecución: duración, éxito de SNMP y hora del último escaneo.
- **Pushgateway** (el componente oficial para trabajos por lotes) recibe esas
  métricas: el Job vive dos minutos y Prometheus no llegaría a leerlas. Se
  instala con el mismo chart de monitorización.
- En el chart de la app, un contenedor más en el Job (imagen pequeña con `curl`,
  fijada por digest) que sube el archivo al Pushgateway después del escaneo.
  Independiente de AWS: funciona con `aws.enabled` o sin él. Se activa con un
  valor del chart (`metricas.enabled`) y si no hay Pushgateway, el Job no falla.
- Panel de Grafana "Escaneo nocturno": evolución de hosts vivos por rango,
  puertos sensibles, hosts nunca vistos, duración y edad del último escaneo.
- Versión: **v1.6.0** (flag nuevo) y chart 0.5.0, desplegadas por Jenkins.

### Verificación (lo que demuestra que está hecha)

- [ ] Monitorización instalada desde el repo; 0 alertas disparadas en reposo
      salvo `Watchdog`.
- [ ] Ensayo 1: un Job que falla a propósito en `topology-scanner` llega a
      Telegram, y luego el "resuelto".
- [ ] Ensayo 2: apagar la VM k3s a mano (`qm shutdown`) → aviso de
      healthchecks.io en Telegram; al encenderla, aviso de recuperación y aviso
      de "nodo reiniciado".
- [ ] Ensayo 3: borrar el chart de monitorización y reinstalar desde el repo deja
      reglas, paneles y avisos igual.
- [ ] v1.6.0 desplegada por Jenkins y el nocturno siguiente aparece en el panel.

## Lo que hace el mantenedor a mano

Crear el bot con BotFather y sacar el chat ID; crear la cuenta de
healthchecks.io, el check y su integración de Telegram; crear el archivo con
los secretos y el Secret; la entrada de NPM para Grafana; y apagar la VM en el
ensayo 2. Claude no ve los valores de los secretos.

## Supuestos a confirmar

- **Que el MiniPC se enciende solo al volver la luz** (opción de BIOS tipo
  "Restore on AC power loss"). La VM k3s tiene `onboot: 1`, así que si Proxmox
  arranca, todo lo demás arranca. Si la BIOS no lo tiene activo, hay que
  activarlo: sin eso, el aviso de recuperación no llegaría nunca.

## Lo que queda para quien construya

- Versiones exactas del chart y de las imágenes; nombres de las métricas; el
  JSON de los paneles; umbrales exactos (26 h, 85 %, minutos del plazo).
- Si el Pushgateway sale del propio `kube-prometheus-stack` o de su chart
  aparte.
- Orden de las tareas, siempre con el ensayo 2 antes de dar la fase por hecha.

## Ideas para después

- SAI + NUT para apagado ordenado de Proxmox.
- Métricas de Jenkins (despliegues, duración, rollbacks) en Grafana.
- Loki para los logs del nocturno.
