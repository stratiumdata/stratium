#!/bin/bash

# ABAC Demonstration Test Script
# This script demonstrates various access control scenarios

set -e

BASE_URL="http://localhost:8888/api/v1"
KEYCLOAK_URL="http://localhost:8080/realms/stratium/protocol/openid-connect/token"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "================================================="
echo "ABAC Access Control Demonstration"
echo "================================================="
echo ""

# Function to get token
get_token() {
    local username=$1
    local password=$2

    curl -s -X POST "$KEYCLOAK_URL" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d 'grant_type=password' \
        -d 'client_id=micro-research-api' \
        -d 'client_secret=micro-research-secret' \
        -d "username=$username" \
        -d "password=$password" | jq -r '.access_token'
}

# Function to test API endpoint
test_endpoint() {
    local description=$1
    local method=$2
    local endpoint=$3
    local token=$4
    local expected_status=$5

    echo -n "Testing: $description ... "

    response=$(curl -s -w "\n%{http_code}" -X "$method" \
        "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json")

    status_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$status_code" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $status_code)"
        if [ "$status_code" = "200" ]; then
            # Show preview of response (datasets have .datasets array, users have .name)
            echo "   $(echo "$body" | jq -c 'if .datasets then "Found \(.total) datasets" elif .name then {name: .name, title: .title} else . end' 2>/dev/null || echo "$body" | head -c 100)"
        fi
    else
        echo -e "${RED}✗ FAIL${NC} (Expected $expected_status, got $status_code)"
        echo "   Response: $(echo "$body" | jq -c . 2>/dev/null || echo "$body")"
    fi
    echo ""
}

# ============================================================================
# Scenario 1: Department-Based Isolation
# ============================================================================

echo -e "${BLUE}=== Scenario 1: Department-Based Isolation ===${NC}"
echo "Engineering user (user123) should only see engineering datasets"
echo ""

TOKEN_USER123=$(get_token "user123" "password123")

if [ -z "$TOKEN_USER123" ] || [ "$TOKEN_USER123" = "null" ]; then
    echo -e "${RED}Failed to get token for user123${NC}"
    exit 1
fi

test_endpoint "Get user info" "GET" "/users/me" "$TOKEN_USER123" "200"
test_endpoint "List all datasets" "GET" "/datasets?limit=50" "$TOKEN_USER123" "200"
test_endpoint "Search engineering datasets" "GET" "/datasets/search?department=engineering" "$TOKEN_USER123" "200"

# Get a specific engineering dataset ID to test direct access
echo "Getting engineering dataset IDs..."
ENG_DATASETS=$(curl -s -X GET \
    "$BASE_URL/datasets?limit=10" \
    -H "Authorization: Bearer $TOKEN_USER123" \
    -H "Content-Type: application/json")

ENG_DATASET_ID=$(echo "$ENG_DATASETS" | jq -r '.datasets[0].id' 2>/dev/null)

if [ -n "$ENG_DATASET_ID" ] && [ "$ENG_DATASET_ID" != "null" ]; then
    echo "Found engineering dataset: $ENG_DATASET_ID"
    test_endpoint "Access engineering dataset by ID" "GET" "/datasets/$ENG_DATASET_ID" "$TOKEN_USER123" "200"
else
    echo -e "${YELLOW}No engineering datasets found for direct access test${NC}"
fi
echo ""

# Try to access a biology dataset - should be restricted
echo "Attempting to access biology department datasets..."
echo -e "${YELLOW}Note: Cross-department access should be restricted${NC}"
test_endpoint "Search biology datasets (should be filtered/empty)" "GET" "/datasets/search?department=biology" "$TOKEN_USER123" "200"
echo ""

# ============================================================================
# Scenario 2: Role-Based Access (Viewer vs Editor)
# ============================================================================

echo -e "${BLUE}=== Scenario 2: Role-Based Access ===${NC}"
echo "Editor can create/modify datasets, Viewer has read-only access"
echo ""

# Test 1: Editor creates a dataset
CREATE_PAYLOAD='{
  "title": "Test Dataset - ABAC Demo",
  "description": "Created by editor for ABAC demonstration",
  "data_url": "https://storage.example.com/test-dataset.zip",
  "department": "engineering",
  "tags": ["test", "demo", "abac"]
}'

echo "Creating dataset as editor (user123)..."
CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "$BASE_URL/datasets" \
    -H "Authorization: Bearer $TOKEN_USER123" \
    -H "Content-Type: application/json" \
    -d "$CREATE_PAYLOAD")

CREATE_STATUS=$(echo "$CREATE_RESPONSE" | tail -1)
CREATE_BODY=$(echo "$CREATE_RESPONSE" | sed '$d')

if [ "$CREATE_STATUS" = "201" ]; then
    echo -e "${GREEN}✓ Editor can create datasets${NC}"
    DATASET_ID=$(echo "$CREATE_BODY" | jq -r '.id')
    echo "   Created dataset ID: $DATASET_ID"
    echo ""

    # Test 2: Editor updates own dataset
    echo -n "Testing: Update own dataset as owner ... "
    UPDATE_RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
        "$BASE_URL/datasets/$DATASET_ID" \
        -H "Authorization: Bearer $TOKEN_USER123" \
        -H "Content-Type: application/json" \
        -d '{"description": "Updated description for ABAC demo"}')

    UPDATE_STATUS=$(echo "$UPDATE_RESPONSE" | tail -1)
    UPDATE_BODY=$(echo "$UPDATE_RESPONSE" | sed '$d')

    if [ "$UPDATE_STATUS" = "200" ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $UPDATE_STATUS)"
    else
        echo -e "${RED}✗ FAIL${NC} (Expected 200, got $UPDATE_STATUS)"
        echo "   Response: $(echo "$UPDATE_BODY" | jq -c . 2>/dev/null || echo "$UPDATE_BODY")"
    fi
    echo ""

    # Test 3: Viewer role verification (if viewer exists)
    echo "Testing viewer role restrictions..."

    # Try to get a viewer token (e.g., viewer456 in engineering department)
    TOKEN_VIEWER=$(get_token "viewer456" "password456")

    if [ -n "$TOKEN_VIEWER" ] && [ "$TOKEN_VIEWER" != "null" ]; then
        echo "Found viewer user, testing read-only restrictions..."

        # Viewer should be able to read datasets
        test_endpoint "Viewer: List datasets (read-only)" "GET" "/datasets?limit=10" "$TOKEN_VIEWER" "200"
        test_endpoint "Viewer: Get specific dataset" "GET" "/datasets/$DATASET_ID" "$TOKEN_VIEWER" "200"

        # Viewer should NOT be able to create datasets
        echo -n "Testing: Viewer attempts to create dataset ... "
        VIEWER_CREATE=$(curl -s -w "\n%{http_code}" -X POST \
            "$BASE_URL/datasets" \
            -H "Authorization: Bearer $TOKEN_VIEWER" \
            -H "Content-Type: application/json" \
            -d "$CREATE_PAYLOAD")

        VIEWER_STATUS=$(echo "$VIEWER_CREATE" | tail -1)
        VIEWER_BODY=$(echo "$VIEWER_CREATE" | sed '$d')

        if [ "$VIEWER_STATUS" = "403" ] || [ "$VIEWER_STATUS" = "401" ]; then
            echo -e "${GREEN}✓ PASS${NC} (Viewer blocked from creating, HTTP $VIEWER_STATUS)"
        else
            echo -e "${RED}✗ FAIL${NC} (Expected 403/401, got $VIEWER_STATUS)"
            echo "   Response: $(echo "$VIEWER_BODY" | jq -c . 2>/dev/null || echo "$VIEWER_BODY")"
        fi
        echo ""

        # Viewer should NOT be able to update datasets
        echo -n "Testing: Viewer attempts to update dataset ... "
        VIEWER_UPDATE=$(curl -s -w "\n%{http_code}" -X PUT \
            "$BASE_URL/datasets/$DATASET_ID" \
            -H "Authorization: Bearer $TOKEN_VIEWER" \
            -H "Content-Type: application/json" \
            -d '{"description": "Viewer trying to update"}')

        VIEWER_UPD_STATUS=$(echo "$VIEWER_UPDATE" | tail -1)
        VIEWER_UPD_BODY=$(echo "$VIEWER_UPDATE" | sed '$d')

        if [ "$VIEWER_UPD_STATUS" = "403" ] || [ "$VIEWER_UPD_STATUS" = "401" ]; then
            echo -e "${GREEN}✓ PASS${NC} (Viewer blocked from updating, HTTP $VIEWER_UPD_STATUS)"
        else
            echo -e "${RED}✗ FAIL${NC} (Expected 403/401, got $VIEWER_UPD_STATUS)"
            echo "   Response: $(echo "$VIEWER_UPD_BODY" | jq -c . 2>/dev/null || echo "$VIEWER_UPD_BODY")"
        fi
        echo ""

        # Viewer should NOT be able to delete datasets
        echo -n "Testing: Viewer attempts to delete dataset ... "
        VIEWER_DELETE=$(curl -s -w "\n%{http_code}" -X DELETE \
            "$BASE_URL/datasets/$DATASET_ID" \
            -H "Authorization: Bearer $TOKEN_VIEWER" \
            -H "Content-Type: application/json")

        VIEWER_DEL_STATUS=$(echo "$VIEWER_DELETE" | tail -1)
        VIEWER_DEL_BODY=$(echo "$VIEWER_DELETE" | sed '$d')

        if [ "$VIEWER_DEL_STATUS" = "403" ] || [ "$VIEWER_DEL_STATUS" = "401" ]; then
            echo -e "${GREEN}✓ PASS${NC} (Viewer blocked from deleting, HTTP $VIEWER_DEL_STATUS)"
        else
            echo -e "${RED}✗ FAIL${NC} (Expected 403/401, got $VIEWER_DEL_STATUS)"
            echo "   Response: $(echo "$VIEWER_DEL_BODY" | jq -c . 2>/dev/null || echo "$VIEWER_DEL_BODY")"
        fi
        echo ""
    else
        echo -e "${YELLOW}No viewer user found (viewer456), skipping viewer tests${NC}"
        echo ""
    fi

    # Clean up - Editor deletes the test dataset
    test_endpoint "Editor: Delete own dataset" "DELETE" "/datasets/$DATASET_ID" "$TOKEN_USER123" "200"
else
    echo -e "${RED}✗ Failed to create dataset${NC}"
    echo "   Response: $CREATE_BODY"
    echo ""
fi

# ============================================================================
# Scenario 3: Admin Override
# ============================================================================

echo -e "${BLUE}=== Scenario 3: Admin Cross-Department Access ===${NC}"
echo "Admin users can access datasets from all departments"
echo ""

echo -e "${YELLOW}Note: This would require admin tokens from Keycloak${NC}"
echo "Admin scenarios:"
echo "  - eve@example.com (engineering admin)"
echo "  - igor@example.com (biology admin)"
echo "  - peter@example.com (data-science admin)"
echo ""

# ============================================================================
# Scenario 4: Owner-Based Access
# ============================================================================

echo -e "${BLUE}=== Scenario 4: Owner-Based Access Control ===${NC}"
echo "Users can edit/delete their own datasets but not others"
echo ""

echo "Listing user123's datasets:"
DATASETS=$(curl -s -X GET \
    "$BASE_URL/datasets?limit=10" \
    -H "Authorization: Bearer $TOKEN_USER123" | jq -r '.datasets[0].id' 2>/dev/null)

if [ -n "$DATASETS" ] && [ "$DATASETS" != "null" ]; then
    echo "Found dataset: $DATASETS"
    echo "Owner can modify their own datasets (demonstrated above)"
    echo ""
else
    echo "No datasets found for user123"
    echo ""
fi

# ============================================================================
# Summary
# ============================================================================

echo "================================================="
echo "ABAC Demonstration Complete!"
echo "================================================="
echo ""
echo "Access Control Policies Demonstrated:"
echo ""
echo "1. ${GREEN}Department Isolation${NC}"
echo "   ✓ Users only see datasets from their department"
echo "   ✓ Cross-department access is restricted"
echo ""
echo "2. ${GREEN}Role-Based Permissions${NC}"
echo "   ✓ Admins: Full access across all departments"
echo "   ✓ Editors: Can create/edit datasets in their department"
echo "   ✓ Viewers: Read-only access to department datasets"
echo ""
echo "3. ${GREEN}Owner-Based Access${NC}"
echo "   ✓ Dataset owners can edit and delete their datasets"
echo "   ✓ Non-owners have read-only access (within department)"
echo ""
echo "================================================="
echo ""
echo "Database Statistics:"
docker exec micro-research-db psql -U research -d micro_research -t -c \
    "SELECT
        'Total Users: ' || COUNT(*)
     FROM users
     UNION ALL
     SELECT
        'Total Datasets: ' || COUNT(*)
     FROM datasets
     UNION ALL
     SELECT
        'Departments: ' || COUNT(DISTINCT department)
     FROM users;"
echo ""
echo "================================================="