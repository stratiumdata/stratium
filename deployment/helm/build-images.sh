#!/bin/bash
#
# Build All Stratium Docker Images for Local Development
# This script builds all Docker images needed for local Kubernetes deployment
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
 _____ _             _   _
/  ___| |           | | (_)
\ `--.| |_ _ __ __ _| |_ _ _   _ _ __ ___
 `--. \ __| '__/ _` | __| | | | | '_ ` _ \
/\__/ / |_| | | (_| | |_| | |_| | | | | | |
\____/ \__|_|  \__,_|\__|_|\__,_|_| |_| |_|

Building Docker Images for Local Development
EOF
echo -e "${NC}"

# Check if we're in the right directory
if [ ! -f "../../go/go.mod" ]; then
    echo -e "${RED}Error: Must run from deployment/helm directory${NC}"
    echo "Usage: cd deployment/helm && ./build-images.sh"
    exit 1
fi

cd ../  # Now in deployment directory

# Detect Kubernetes environment
K8S_ENV="docker-desktop"
if kubectl config current-context | grep -q "minikube"; then
    K8S_ENV="minikube"
    echo -e "${YELLOW}Detected Minikube environment${NC}"
    echo -e "${YELLOW}Configuring Docker to use Minikube's daemon...${NC}"
    eval $(minikube docker-env)
elif kubectl config current-context | grep -q "kind"; then
    K8S_ENV="kind"
    CLUSTER_NAME=$(kubectl config current-context | sed 's/kind-//')
    echo -e "${YELLOW}Detected kind environment: ${CLUSTER_NAME}${NC}"
fi

# Build function
build_image() {
    local name=$1
    local dockerfile=$2
    local service_name=$3
    local service_port=$4
    local build_context=$5
    local version_tag=$6

    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Building: ${name}${NC}"
    echo -e "${BLUE}========================================${NC}"

    if [ -n "$service_name" ]; then
        docker build -t "stratiumdata/${name}:latest" \
            -f "${dockerfile}" \
            --build-arg SERVICE_NAME="${service_name}" \
            --build-arg SERVICE_PORT="${service_port}" \
            ${build_context}
    else
        docker build -t "stratiumdata/${name}:latest" \
            -f "${dockerfile}" \
            ${build_context}
    fi

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Successfully built stratiumdata/${name}:latest${NC}"
        if [ -n "$version_tag" ]; then
            local remote_image="${ECR_REGISTRY}/stratiumdata-${name}:${version_tag}"
            echo -e "${YELLOW}Tagging stratiumdata/${name}:latest as ${remote_image}${NC}"
            docker tag "stratiumdata/${name}:latest" "${remote_image}"
            echo -e "${YELLOW}Pushing ${remote_image}${NC}"
            docker push "${remote_image}"
        fi

        # Load into kind if needed
        if [ "$K8S_ENV" = "kind" ]; then
            echo -e "${YELLOW}Loading image into kind cluster...${NC}"
            kind load docker-image "stratiumdata/${name}:latest" --name "${CLUSTER_NAME}"
        fi
    else
        echo -e "${RED}✗ Failed to build stratiumdata/${name}:latest${NC}"
        exit 1
    fi
}

# Build selection helper
build_selection() {
    local target=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    local version_tag="$2"
    case "$target" in
        platform)
            build_image "platform" "Dockerfile" "platform-server" "50051" ".." "$version_tag"
            ;;
        key-manager|keymanager)
            build_image "key-manager" "Dockerfile" "key-manager-server" "50052" ".." "$version_tag"
            ;;
        key-access|keyaccess)
            build_image "key-access" "Dockerfile" "key-access-server" "50053" ".." "$version_tag"
            ;;
        pap)
            build_image "pap" "Dockerfile.pap" "" "" ".." "$version_tag"
            ;;
        pap-ui|papui)
            build_image "pap-ui" "../pap-ui/Dockerfile" "" "" "../pap-ui" "$version_tag"
            ;;
        all)
            build_selection "platform" "$version_tag"
            build_selection "key-manager" "$version_tag"
            build_selection "key-access" "$version_tag"
            build_selection "pap" "$version_tag"
            build_selection "pap-ui" "$version_tag"
            ;;
        *)
            echo -e "${RED}Unknown image '$1'. Supported values: platform, key-manager, key-access, pap, pap-ui, all${NC}"
            exit 1
            ;;
    esac
}

echo -e "${BLUE}Starting build process...${NC}"
echo ""

VERSION_TAG=""
PARAM_IMAGES=()
for arg in "$@"; do
    case "$arg" in
        --tag=*)
            VERSION_TAG="${arg#--tag=}"
            ;;
        --help|-h)
            echo "Usage: ./build-images.sh [--tag=vX.Y.Z] [platform|key-manager|key-access|pap|pap-ui|all ...]"
            exit 0
            ;;
        *)
            PARAM_IMAGES+=("$arg")
            ;;
    esac
done

if [ -z "$VERSION_TAG" ] && [ -n "$ECR_TAG" ]; then
    VERSION_TAG="$ECR_TAG"
fi

if [ -n "$VERSION_TAG" ] && [ -z "$ECR_REGISTRY" ]; then
    echo -e "${RED}Error: --tag requires ECR_REGISTRY to be set (e.g., 536176198371.dkr.ecr.us-east-2.amazonaws.com)${NC}"
    exit 1
fi

if [ $# -eq 0 ] || [ ${#PARAM_IMAGES[@]} -eq 0 ]; then
    build_selection "all" "$VERSION_TAG"
else
    for image in "${PARAM_IMAGES[@]}"; do
        build_selection "$image" "$VERSION_TAG"
    done
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All images built successfully! 🎉${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# List built images
echo -e "${BLUE}Built images:${NC}"
docker images | grep stratiumdata | grep latest

echo ""
echo -e "${BLUE}Next steps:${NC}"
if [ "$K8S_ENV" = "kind" ]; then
    echo -e "  ${GREEN}✓ Images loaded into kind cluster${NC}"
    echo -e "  You can now deploy with: ${YELLOW}helm install stratium ./stratium -n stratium --create-namespace -f stratium/values-local.yaml${NC}"
elif [ "$K8S_ENV" = "minikube" ]; then
    echo -e "  ${GREEN}✓ Images built in Minikube's Docker daemon${NC}"
    echo -e "  You can now deploy with: ${YELLOW}helm install stratium ./stratium -n stratium --create-namespace -f stratium/values-local.yaml${NC}"
else
    echo -e "  ${GREEN}✓ Images available in Docker Desktop${NC}"
    echo -e "  You can now deploy with: ${YELLOW}helm install stratium ./stratium -n stratium --create-namespace -f stratium/values-local.yaml${NC}"
fi

echo ""
echo -e "${YELLOW}Or use the quick-start script: ${GREEN}cd helm && ./quick-start.sh${NC}"
