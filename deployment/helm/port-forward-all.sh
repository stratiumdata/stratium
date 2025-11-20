#!/bin/bash
#
# Port Forward All Stratium Services
# This script sets up port forwarding for all Stratium services to localhost
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

NAMESPACE="${NAMESPACE:-stratium}"

echo -e "${BLUE}Starting port forwards for Stratium services in namespace: ${NAMESPACE}${NC}"
echo ""

# Check if namespace exists
if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    echo -e "${RED}Namespace ${NAMESPACE} does not exist.${NC}"
    echo "Please install Stratium first or set the correct namespace."
    exit 1
fi

# Check if pods are running
echo -e "${BLUE}Checking pod status...${NC}"
READY_PODS=$(kubectl get pods -n "${NAMESPACE}" --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' ')
TOTAL_PODS=$(kubectl get pods -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -d ' ')

if [ "$READY_PODS" -eq 0 ]; then
    echo -e "${RED}No pods are running in namespace ${NAMESPACE}.${NC}"
    echo "Please wait for pods to start or check the deployment."
    exit 1
fi

echo -e "${GREEN}Found ${READY_PODS}/${TOTAL_PODS} pods running${NC}"
echo ""

# Function to start port forward
start_port_forward() {
    local service=$1
    local local_port=$2
    local service_port=$3
    local description=$4

    echo -e "${YELLOW}Setting up port forward: ${description}${NC}"
    kubectl port-forward -n "${NAMESPACE}" "svc/${service}" "${local_port}:${service_port}" &
    sleep 1
}

# Start port forwards
echo -e "${BLUE}Starting port forwards...${NC}"
echo ""

start_port_forward "stratium-pap-ui" 3000 80 "PAP Web UI"
start_port_forward "stratium-keycloak" 8080 8080 "Keycloak Admin Console"
start_port_forward "stratium-pap" 8090 8090 "PAP REST API"
start_port_forward "stratium-platform" 50051 50051 "Platform Service (gRPC)"
start_port_forward "stratium-key-manager" 50052 50052 "Key Manager Service (gRPC)"
start_port_forward "stratium-key-access" 50053 50053 "Key Access Service (gRPC)"
start_port_forward "stratium-envoy" 8081 8081 "Envoy gRPC-Web Proxy"
start_port_forward "stratium-postgresql" 5432 5432 "PostgreSQL Database"
start_port_forward "stratium-redis" 6379 6379 "Redis Cache"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All port forwards are running!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Access services at:${NC}"
echo ""
echo -e "  ${YELLOW}PAP Web UI:${NC}              http://localhost:3000"
echo -e "  ${YELLOW}Keycloak Admin:${NC}          http://localhost:8080 (admin / admin)"
echo -e "  ${YELLOW}PAP REST API:${NC}            http://localhost:8090"
echo ""
echo -e "  ${YELLOW}Platform Service:${NC}        localhost:50051 (gRPC)"
echo -e "  ${YELLOW}Key Manager Service:${NC}     localhost:50052 (gRPC)"
echo -e "  ${YELLOW}Key Access Service:${NC}      localhost:50053 (gRPC)"
echo -e "  ${YELLOW}Envoy gRPC-Web:${NC}          localhost:8081"
echo ""
echo -e "  ${YELLOW}PostgreSQL:${NC}              localhost:5432 (keycloak / keycloak_password)"
echo -e "  ${YELLOW}Redis:${NC}                   localhost:6379"
echo ""
echo -e "${BLUE}Test with:${NC}"
echo ""
echo -e "  curl http://localhost:8090/health"
echo -e "  grpcurl -plaintext localhost:50051 list"
echo ""
echo -e "${RED}Press Ctrl+C to stop all port forwards${NC}"
echo ""

# Handle Ctrl+C
trap 'echo -e "\n${YELLOW}Stopping all port forwards...${NC}"; pkill -P $$; exit 0' INT TERM

# Wait for all background jobs
wait