#!/bin/bash
#
# Quick Start Script for Stratium Helm Deployment
# This script helps you deploy Stratium to a Kubernetes cluster
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
NAMESPACE="${NAMESPACE:-stratium}"
RELEASE_NAME="${RELEASE_NAME:-stratium}"
HELM_CHART="./stratium"

echo -e "${BLUE}"
cat << "EOF"
 _____ _             _   _
/  ___| |           | | (_)
\ `--.| |_ _ __ __ _| |_ _ _   _ _ __ ___
 `--. \ __| '__/ _` | __| | | | | '_ ` _ \
/\__/ / |_| | | (_| | |_| | |_| | | | | | |
\____/ \__|_|  \__,_|\__|_|\__,_|_| |_| |_|

Zero Trust Data Fabric - Kubernetes Deployment
EOF
echo -e "${NC}"

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}kubectl not found. Please install kubectl.${NC}"
        exit 1
    fi

    # Check helm
    if ! command -v helm &> /dev/null; then
        echo -e "${RED}helm not found. Please install Helm 3.8+.${NC}"
        exit 1
    fi

    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}Cannot connect to Kubernetes cluster. Please check your kubeconfig.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ All prerequisites met${NC}"
}

# Create namespace
create_namespace() {
    echo -e "${BLUE}Creating namespace: ${NAMESPACE}${NC}"
    if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
        echo -e "${YELLOW}Namespace ${NAMESPACE} already exists${NC}"
    else
        kubectl create namespace "${NAMESPACE}"
        echo -e "${GREEN}✓ Namespace created${NC}"
    fi
}

# Check for custom values file
check_values_file() {
    if [ -n "${VALUES_FILE}" ] && [ -f "${VALUES_FILE}" ]; then
        echo -e "${GREEN}Using custom values file: ${VALUES_FILE}${NC}"
        VALUES_ARG="-f ${VALUES_FILE}"
    else
        echo -e "${YELLOW}No custom values file specified, using defaults${NC}"
        echo -e "${YELLOW}For production, create a custom values file and set VALUES_FILE environment variable${NC}"
        VALUES_ARG=""
    fi
}

# Deploy with Helm
deploy_helm() {
    echo -e "${BLUE}Deploying Stratium with Helm...${NC}"

    helm upgrade --install "${RELEASE_NAME}" "${HELM_CHART}" \
        --namespace "${NAMESPACE}" \
        ${VALUES_ARG} \
        --wait \
        --timeout 10m

    echo -e "${GREEN}✓ Deployment complete${NC}"
}

# Display access information
show_access_info() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Deployment successful!${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    # Get pod status
    echo -e "${BLUE}Pod Status:${NC}"
    kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}"
    echo ""

    # Show access commands
    echo -e "${BLUE}Access Services:${NC}"
    echo ""
    echo -e "${YELLOW}PAP UI:${NC}"
    echo "  kubectl port-forward -n ${NAMESPACE} svc/${RELEASE_NAME}-pap-ui 3000:80"
    echo "  Then visit: http://localhost:3000"
    echo ""

    echo -e "${YELLOW}Keycloak Admin:${NC}"
    echo "  kubectl port-forward -n ${NAMESPACE} svc/${RELEASE_NAME}-keycloak 8080:8080"
    echo "  Then visit: http://localhost:8080"
    echo ""

    echo -e "${YELLOW}PAP API:${NC}"
    echo "  kubectl port-forward -n ${NAMESPACE} svc/${RELEASE_NAME}-pap 8090:8090"
    echo "  Then access: http://localhost:8090"
    echo ""

    echo -e "${BLUE}View Logs:${NC}"
    echo "  kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/component=platform --tail=100 -f"
    echo ""

    echo -e "${BLUE}View All Resources:${NC}"
    echo "  kubectl get all -n ${NAMESPACE} -l app.kubernetes.io/instance=${RELEASE_NAME}"
    echo ""

    echo -e "${RED}IMPORTANT SECURITY NOTES:${NC}"
    echo -e "${YELLOW}1. Change default passwords before production use${NC}"
    echo -e "${YELLOW}2. Configure TLS/HTTPS for external access${NC}"
    echo -e "${YELLOW}3. Review and customize security settings${NC}"
    echo ""
}

# Main execution
main() {
    echo -e "${BLUE}Starting Stratium deployment...${NC}"
    echo ""

    check_prerequisites
    create_namespace
    check_values_file
    deploy_helm
    show_access_info

    echo -e "${GREEN}Setup complete! 🎉${NC}"
}

# Run main function
main "$@"