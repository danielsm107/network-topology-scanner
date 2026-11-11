{{/* Nombre base de los recursos: el del release, con el del chart si no lo lleva */}}
{{- define "topology-scanner.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "topology-scanner.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "topology-scanner.imagen" -}}
{{- /* required devuelve el valor: se descarta para que no se cuele en la imagen */ -}}
{{- $_ := required "image.tag es obligatorio (tag fijo, nunca latest)" .Values.image.tag -}}
{{- if eq (toString .Values.image.tag) "latest" -}}
{{- fail "image.tag no puede ser latest: el clúster tiene que correr una versión conocida" -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository (toString .Values.image.tag) -}}
{{- end -}}

{{/*
Lo común a los dos pods: red del nodo (para ver las MACs del segmento), sin
root y solo NET_RAW + NET_ADMIN + NET_BIND_SERVICE (las del setcap de la imagen:
rpcinfo de -sV sale desde un puerto <1024). Sin privileged ni allowPrivilegeEscalation:
false, que anula las capacidades de archivo de nmap (runbook de la fase 1).
*/}}
{{- define "topology-scanner.podComun" -}}
hostNetwork: true
dnsPolicy: ClusterFirstWithHostNet
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
{{- end -}}

{{/* El volumen del historial; cada pod añade los suyos detrás */}}
{{- define "topology-scanner.volumenDatos" -}}
- name: datos
  persistentVolumeClaim:
    claimName: {{ include "topology-scanner.fullname" . }}-datos
{{- end -}}

{{- define "topology-scanner.contenedorComun" -}}
image: {{ include "topology-scanner.imagen" . }}
imagePullPolicy: {{ .Values.image.pullPolicy }}
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_RAW, NET_ADMIN, NET_BIND_SERVICE]
{{- end -}}

{{/* Hora local (TZ) y credenciales SNMPv3 del Secret creado a mano; optional: sin SNMP no hace falta */}}
{{- define "topology-scanner.envComun" -}}
- name: TZ
  value: {{ .Values.zonaHoraria | quote }}
{{- range list "TOPOLOGY_SNMP_USER" "TOPOLOGY_SNMP_AUTH_KEY" "TOPOLOGY_SNMP_PRIV_KEY" }}
- name: {{ . }}
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.snmpSecret }}
      key: {{ . }}
      optional: true
{{- end }}
{{- end -}}


{{/*
El contenedor del escaneo nocturno. Sin aws.enabled, el HTML y el CSV van al
directorio de trabajo (/data); con aws.enabled va como initContainer y deja en
/salida (emptyDir) lo que sube después el contenedor de subida.
*/}}
{{- define "topology-scanner.contenedorEscaneo" -}}
- name: escaneo
  {{- include "topology-scanner.contenedorComun" . | nindent 2 }}
  args:
    {{- range (required "escaneo.rangos no puede estar vacío" .Values.escaneo.rangos) }}
    - {{ . | quote }}
    {{- end }}
    - --history-db
    - /data/historial.db
    {{- if .Values.escaneo.osDetection }}
    - --os-detection
    {{- end }}
    {{- if .Values.escaneo.snmp }}
    - --snmp
    - {{ join "," .Values.escaneo.snmp | quote }}
    {{- end }}
    {{- if .Values.aws.enabled }}
    - --output
    - /salida/network_topology.html
    - --csv
    - /salida/inventory.csv
    - --changes-dir
    - /salida/cambios
    - --history-backup
    - /salida/historial.db
    {{- end }}
    {{- if .Values.metricas.enabled }}
    - --metrics-file
    - /salida/metricas.prom
    {{- end }}
  env:
    {{- include "topology-scanner.envComun" . | nindent 4 }}
  volumeMounts:
    - name: datos
      mountPath: /data
    {{- if include "topology-scanner.conSalida" . }}
    - name: salida
      mountPath: /salida
    {{- end }}
  resources:
    {{- toYaml .Values.resources.escaneo | nindent 4 }}
{{- end -}}


{{/*
"true" si el Job deja archivos para un contenedor posterior (subida a AWS o
métricas al Pushgateway): entonces el escaneo es initContainer y hay emptyDir.
*/}}
{{- define "topology-scanner.conSalida" -}}
{{- if or .Values.aws.enabled .Values.metricas.enabled }}true{{ end -}}
{{- end -}}
