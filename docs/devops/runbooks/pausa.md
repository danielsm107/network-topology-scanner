# Pausa y reanudación del homelab

Para dejar todo parado una temporada (sin escaneos, sin despliegues y sin avisos)
y volver a arrancarlo sin sorpresas. No es una fase: es una operación.

Primera pausa: 2026-11-17.

## Qué se para y qué no

| Pieza | En pausa | Por qué |
|---|---|---|
| CronJob del escaneo | `suspend: true` | Al encender la VM no recupera el escaneo perdido, y evita el límite de 100 ejecuciones perdidas de los CronJob |
| VM de k3s | apagada (Shutdown) | Se paran Jenkins, la web, Prometheus, Grafana y Loki |
| healthchecks.io | check en pausa | Si no, avisa por Telegram de que los pings han dejado de llegar |
| AWS | nada | Sin escaneos no se sube nada; los informes caducan a los 90 días y la copia del historial se conserva. Céntimos al mes |
| GitHub Actions | nada | Solo corre con push o PR |

## Pausar

Con `KUBECONFIG` apuntando al clúster (ver [03-kubernetes.md](03-kubernetes.md)):

1. Comprobar que no hay un escaneo en marcha (`ACTIVE` = 0):

   ```bash
   kubectl -n topology-scanner get cronjob topology-scanner-escaneo
   ```

2. Suspender el CronJob:

   ```bash
   kubectl -n topology-scanner patch cronjob topology-scanner-escaneo -p '{"spec":{"suspend":true}}'
   ```

3. Pausar el check en healthchecks.io (botón *Pause*). **Antes** de apagar la VM.
4. Apagar la VM de k3s con **Shutdown**, no con *Stop*: *Stop* es quitarle la
   corriente, y Prometheus, Loki y Jenkins no guardan lo que tienen en memoria.
   Desde la interfaz de Proxmox o con la API (`POST .../qemu/<vmid>/status/shutdown`
   con el token de [02-proxmox-vm.md](02-proxmox-vm.md)).

## Reanudar

1. Encender la VM y esperar a que el nodo esté `Ready` (`kubectl get nodes`) y los
   pods de `monitoring` y `topology-scanner` en `Running`.
2. Quitar la suspensión:

   ```bash
   kubectl -n topology-scanner patch cronjob topology-scanner-escaneo -p '{"spec":{"suspend":false}}'
   ```

3. Lanzar un escaneo a mano para no esperar a las 3:00:

   ```bash
   kubectl -n topology-scanner create job --from=cronjob/topology-scanner-escaneo reanudacion-$(date +%Y%m%d)
   ```

   Comprobar que termina `Complete` y que sale en el panel "Escaneo nocturno" de Grafana.
4. Reanudar el check en healthchecks.io.

## A tener en cuenta

- **Avisos al arrancar.** Tras una pausa de más de 26 h, `NightlyScanNotSucceeded`
  y `ScanMetricsStale` pueden saltar por Telegram en cuanto Prometheus evalúe las
  reglas. Son esperables: se resuelven solos con el escaneo del paso 3.
- **Jenkins puede deshacer la suspensión.** El `suspend` se pone con `kubectl`, fuera
  de Helm: si durante la pausa se publica una versión y Jenkins la despliega al
  encender, el `helm upgrade` deja el CronJob otra vez activo. Si eso no se quiere,
  no publicar tags hasta reanudar, o volver a suspender después del despliegue.
- **Sin suspender,** al encender la VM el CronJob lanza el escaneo de las 3:00
  pendiente (pasó el 2026-11-17, ver [07-logs.md](07-logs.md)). No es un fallo, pero
  en una pausa larga se prefiere arrancar a propósito.
