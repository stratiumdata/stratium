{{/*
Expand the name of the chart.
*/}}
{{- define "stratium.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "stratium.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "stratium.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "stratium.labels" -}}
helm.sh/chart: {{ include "stratium.chart" . }}
{{ include "stratium.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "stratium.selectorLabels" -}}
app.kubernetes.io/name: {{ include "stratium.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-specific labels
*/}}
{{- define "stratium.componentLabels" -}}
{{- $component := . -}}
app.kubernetes.io/component: {{ $component }}
{{- end }}

{{/*
PostgreSQL labels
*/}}
{{- define "stratium.postgresql.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "postgresql" }}
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "stratium.postgresql.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "postgresql" }}
{{- end }}

{{/*
Redis labels
*/}}
{{- define "stratium.redis.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "redis" }}
{{- end }}

{{/*
Redis selector labels
*/}}
{{- define "stratium.redis.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "redis" }}
{{- end }}

{{/*
Keycloak labels
*/}}
{{- define "stratium.keycloak.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "keycloak" }}
{{- end }}

{{/*
Keycloak selector labels
*/}}
{{- define "stratium.keycloak.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "keycloak" }}
{{- end }}

{{/*
Platform labels
*/}}
{{- define "stratium.platform.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "platform" }}
{{- end }}

{{/*
Platform selector labels
*/}}
{{- define "stratium.platform.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "platform" }}
{{- end }}

{{/*
Key Manager labels
*/}}
{{- define "stratium.keyManager.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "key-manager" }}
{{- end }}

{{/*
Key Manager selector labels
*/}}
{{- define "stratium.keyManager.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "key-manager" }}
{{- end }}

{{/*
Key Access labels
*/}}
{{- define "stratium.keyAccess.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "key-access" }}
{{- end }}

{{/*
Key Access selector labels
*/}}
{{- define "stratium.keyAccess.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "key-access" }}
{{- end }}

{{/*
PAP labels
*/}}
{{- define "stratium.pap.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "pap" }}
{{- end }}

{{/*
PAP selector labels
*/}}
{{- define "stratium.pap.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "pap" }}
{{- end }}

{{/*
PAP UI labels
*/}}
{{- define "stratium.papUI.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "pap-ui" }}
{{- end }}

{{/*
PAP UI selector labels
*/}}
{{- define "stratium.papUI.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "pap-ui" }}
{{- end }}

{{/*
Envoy labels
*/}}
{{- define "stratium.envoy.labels" -}}
{{ include "stratium.labels" . }}
{{ include "stratium.componentLabels" "envoy" }}
{{- end }}

{{/*
Envoy selector labels
*/}}
{{- define "stratium.envoy.selectorLabels" -}}
{{ include "stratium.selectorLabels" . }}
{{ include "stratium.componentLabels" "envoy" }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "stratium.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Return the proper image name
*/}}
{{- define "stratium.image" -}}
{{- $registryName := .registry -}}
{{- $repositoryName := .repository -}}
{{- $tag := .tag | toString -}}
{{- if .global }}
    {{- if and .global.imageRegistry (eq .registry "") }}
        {{- $registryName = .global.imageRegistry -}}
    {{- end -}}
{{- end -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Utility BusyBox image used by init containers
*/}}
{{- define "stratium.busyboxImage" -}}
{{- $registryPrefix := "" -}}
{{- if .Values.global.imageRegistry }}
  {{- $registryPrefix = printf "%s/" .Values.global.imageRegistry -}}
{{- end }}
{{- printf "%sbusybox:1.36" $registryPrefix -}}
{{- end }}

{{/*
Cluster domain helper (defaults to cluster.local)
*/}}
{{- define "stratium.clusterDomain" -}}
{{- default "cluster.local" .Values.global.clusterDomain -}}
{{- end }}

{{/*
Secret name helpers (support external/managed secrets)
*/}}
{{- define "stratium.stratiumSecretName" -}}
{{- default (printf "%s-stratium-secret" (include "stratium.fullname" .)) .Values.secrets.stratium.name -}}
{{- end }}

{{- define "stratium.keycloakSecretName" -}}
{{- default (printf "%s-keycloak-secret" (include "stratium.fullname" .)) .Values.secrets.keycloak.name -}}
{{- end }}

{{- define "stratium.postgresqlSecretName" -}}
{{- default (printf "%s-postgresql-secret" (include "stratium.fullname" .)) .Values.secrets.postgresql.name -}}
{{- end }}

{{/*
Shared external egress rule for network policies
*/}}
{{- define "stratium.networkPolicy.externalEgress" -}}
{{- $np := .Values.security.networkPolicy }}
{{- if and $np.externalEgress.enabled $np.externalEgress.cidrs }}
- to:
  {{- range $np.externalEgress.cidrs }}
  - ipBlock:
      cidr: {{ . }}
  {{- end }}
  ports:
  {{- range $np.externalEgress.ports }}
  - protocol: TCP
    port: {{ . }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Fully qualified hostname for the bundled PostgreSQL service
*/}}
{{- define "stratium.postgresql.host" -}}
{{- $domain := include "stratium.clusterDomain" . -}}
{{- printf "%s.%s.svc.%s" (include "stratium.postgresql.serviceName" .) .Release.Namespace $domain -}}
{{- end }}

{{/*
Return the proper Storage Class
*/}}
{{- define "stratium.storageClass" -}}
{{- $storageClass := .storageClass -}}
{{- if .global -}}
    {{- if .global.storageClass -}}
        {{- $storageClass = .global.storageClass -}}
    {{- end -}}
{{- end -}}
{{- if $storageClass -}}
storageClassName: {{ $storageClass | quote }}
{{- end -}}
{{- end -}}

{{/*
Service names
*/}}
{{- define "stratium.postgresql.serviceName" -}}
{{- printf "%s-postgresql" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.redis.serviceName" -}}
{{- printf "%s-redis" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.keycloak.serviceName" -}}
{{- printf "%s-keycloak" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.keycloak.realm" -}}
{{- default "stratium" .Values.keycloak.realm -}}
{{- end }}

{{- define "stratium.keycloak.issuerURL" -}}
{{- $realm := include "stratium.keycloak.realm" . -}}
{{- if .Values.keycloak.config.issuerURL }}
{{- .Values.keycloak.config.issuerURL -}}
{{- else if and .Values.keycloak.ingress.enabled .Values.keycloak.config.hostname }}
{{- printf "https://%s/realms/%s" .Values.keycloak.config.hostname $realm -}}
{{- else -}}
{{- printf "http://%s:%v/realms/%s" (include "stratium.keycloak.serviceName" .) .Values.keycloak.service.port $realm -}}
{{- end }}
{{- end }}

{{- define "stratium.platform.serviceName" -}}
{{- printf "%s-platform" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.keyManager.serviceName" -}}
{{- printf "%s-key-manager" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.keyAccess.serviceName" -}}
{{- printf "%s-key-access" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.pap.serviceName" -}}
{{- printf "%s-pap" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.papUI.serviceName" -}}
{{- printf "%s-pap-ui" (include "stratium.fullname" .) }}
{{- end }}

{{- define "stratium.envoy.serviceName" -}}
{{- printf "%s-envoy" (include "stratium.fullname" .) }}
{{- end }}
