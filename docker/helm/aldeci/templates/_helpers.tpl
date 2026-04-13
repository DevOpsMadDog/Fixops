{{/*
Expand the name of the chart.
*/}}
{{- define "aldeci.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "aldeci.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label value: "chart-name-version"
*/}}
{{- define "aldeci.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace — supports namespaceOverride
*/}}
{{- define "aldeci.namespace" -}}
{{- if .Values.namespaceOverride }}
{{- .Values.namespaceOverride }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Common labels applied to all resources
*/}}
{{- define "aldeci.labels" -}}
helm.sh/chart: {{ include "aldeci.chart" . }}
app.kubernetes.io/name: {{ include "aldeci.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aldeci-platform
{{- end }}

{{/*
Selector labels for API
*/}}
{{- define "aldeci.api.selectorLabels" -}}
app.kubernetes.io/name: aldeci-api
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Selector labels for UI
*/}}
{{- define "aldeci.ui.selectorLabels" -}}
app.kubernetes.io/name: aldeci-ui
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ui
{{- end }}

{{/*
API service account name
*/}}
{{- define "aldeci.api.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- printf "%s-api" (include "aldeci.fullname" .) }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
UI service account name
*/}}
{{- define "aldeci.ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- printf "%s-ui" (include "aldeci.fullname" .) }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret name — use existingSecret if provided, otherwise chart-managed
*/}}
{{- define "aldeci.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "aldeci.fullname" .) }}
{{- end }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "aldeci.configmapName" -}}
{{- printf "%s-config" (include "aldeci.fullname" .) }}
{{- end }}

{{/*
PVC name for data volume
*/}}
{{- define "aldeci.pvc.data" -}}
{{- if .Values.persistence.data.existingClaim }}
{{- .Values.persistence.data.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "aldeci.fullname" .) }}
{{- end }}
{{- end }}

{{/*
PVC name for logs volume
*/}}
{{- define "aldeci.pvc.logs" -}}
{{- if .Values.persistence.logs.existingClaim }}
{{- .Values.persistence.logs.existingClaim }}
{{- else }}
{{- printf "%s-logs" (include "aldeci.fullname" .) }}
{{- end }}
{{- end }}

{{/*
PVC name for backups volume
*/}}
{{- define "aldeci.pvc.backups" -}}
{{- if .Values.persistence.backups.existingClaim }}
{{- .Values.persistence.backups.existingClaim }}
{{- else }}
{{- printf "%s-backups" (include "aldeci.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "aldeci.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Storage class — global overrides per-volume
*/}}
{{- define "aldeci.storageClass" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- end }}
{{- end }}
