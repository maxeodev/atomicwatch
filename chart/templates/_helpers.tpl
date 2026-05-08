{{/*
Expand the name of the chart.
*/}}
{{- define "atomicwatch.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "atomicwatch.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "atomicwatch.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "atomicwatch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: dashboard
app.kubernetes.io/part-of: atomicwatch
{{- end }}

{{/*
Selector labels
*/}}
{{- define "atomicwatch.selectorLabels" -}}
app.kubernetes.io/name: {{ include "atomicwatch.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
