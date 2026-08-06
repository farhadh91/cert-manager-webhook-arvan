{{/* vim: set filetype=mustache: */}}
{{- define "cert-manager-webhook-arvan.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cert-manager-webhook-arvan.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "cert-manager-webhook-arvan.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "cert-manager-webhook-arvan.labels" -}}
app: {{ include "cert-manager-webhook-arvan.name" . }}
app.kubernetes.io/name: {{ include "cert-manager-webhook-arvan.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
chart: {{ include "cert-manager-webhook-arvan.chart" . }}
release: {{ .Release.Name }}
heritage: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels. Kept to the two labels the original chart selected on, so an
existing Deployment can be upgraded in place.
*/}}
{{- define "cert-manager-webhook-arvan.selectorLabels" -}}
app: {{ include "cert-manager-webhook-arvan.name" . }}
release: {{ .Release.Name }}
{{- end -}}

{{- define "cert-manager-webhook-arvan.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "cert-manager-webhook-arvan.fullname" .) }}
{{- end -}}

{{- define "cert-manager-webhook-arvan.rootCAIssuer" -}}
{{ printf "%s-ca" (include "cert-manager-webhook-arvan.fullname" .) }}
{{- end -}}

{{- define "cert-manager-webhook-arvan.rootCACertificate" -}}
{{ printf "%s-ca" (include "cert-manager-webhook-arvan.fullname" .) }}
{{- end -}}

{{- define "cert-manager-webhook-arvan.servingCertificate" -}}
{{ printf "%s-webhook-tls" (include "cert-manager-webhook-arvan.fullname" .) }}
{{- end -}}
