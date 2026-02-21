{{/*
ALdeci 6-Suite Helm helpers
*/}}

{{- define "aldeci.fullname" -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aldeci.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aldeci
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "aldeci.selectorLabels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}

{{/*
Generate environment variables from global.env
*/}}
{{- define "aldeci.globalEnv" -}}
{{- range $key, $val := .Values.global.env }}
- name: {{ $key }}
  value: {{ $val | quote }}
{{- end }}
{{- end -}}

