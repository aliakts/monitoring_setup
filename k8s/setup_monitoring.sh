#!/bin/bash

CLUSTER_NAME="<CLUSTER_NAME>"
PROMETHEUS_HOST="http://<PROMETHEUS_IP>:9090"
LOKI_HOST="http://<LOKI_IP>:3100"

helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm upgrade --install --atomic --timeout 300s grafana-k8s-monitoring grafana/k8s-monitoring \
  --namespace "kube-monitoring" --create-namespace --values - <<EOF
cluster:
  name: ${CLUSTER_NAME}
externalServices:
  prometheus:
    host: ${PROMETHEUS_HOST}
    writeEndpoint: /api/v1/push
  loki:
    host: ${LOKI_HOST}
    writeEndpoint: /loki/api/v1/push
metrics:
  enabled: true
  alloy:
    metricsTuning:
      useIntegrationAllowList: true
  cost:
    enabled: false
  kepler:
    enabled: false
  node-exporter:
    enabled: true
logs:
  enabled: true
  pod_logs:
    enabled: true
  cluster_events:
    enabled: true
traces:
  enabled: false
receivers:
  grpc:
    enabled: false
  http:
    enabled: false
  zipkin:
    enabled: false
  grafanaCloudMetrics:
    enabled: false
opencost:
  enabled: false
kube-state-metrics:
  enabled: true
prometheus-node-exporter:
  enabled: true
prometheus-operator-crds:
  enabled: true
kepler:
  enabled: false
alloy: {}
alloy-events: {}
alloy-logs: {}
EOF
