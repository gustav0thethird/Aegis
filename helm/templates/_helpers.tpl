{{/* Expand the name of the chart. */}}
{{- define "aegis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "aegis.fullname" -}}
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

{{- define "aegis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "aegis.labels" -}}
helm.sh/chart: {{ include "aegis.chart" . }}
{{ include "aegis.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "aegis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "aegis.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aegis.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Name of the Secret holding DATABASE_URL / REDIS_URL / ADMIN_PASSWORD. */}}
{{- define "aegis.secretName" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else }}
{{- include "aegis.fullname" . }}
{{- end }}
{{- end }}

{{/* Container image reference. */}}
{{- define "aegis.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
Secret-backed environment, shared by the broker Deployment and the migration
Job so a migration can never run against different configuration than the app.
Emits list items only — the caller supplies the `env:` key.
*/}}
{{- define "aegis.secretEnv" -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "aegis.secretName" . }}
      key: database-url
- name: REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "aegis.secretName" . }}
      key: redis-url
- name: ADMIN_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "aegis.secretName" . }}
      key: admin-password
- name: AUTH_PATH
  value: {{ .Values.auth.authPath | quote }}
{{- end }}
