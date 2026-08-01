{{- define "pgkms.name" -}}pg-kms-gateway{{- end -}}
{{- define "pgkms.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "pgkms.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "pgkms.labels" -}}
app.kubernetes.io/name: {{ include "pgkms.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
{{- define "pgkms.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "pgkms.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
