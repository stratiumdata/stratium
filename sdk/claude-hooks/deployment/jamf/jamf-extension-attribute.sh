#!/bin/bash
# ============================================================
# Jamf Pro Extension Attribute: Stratium Hooks Version
# ============================================================
# Reports the installed version of @stratium/claude-hooks for
# Jamf inventory and smart group targeting.
#
# Deployment: Jamf Pro > Computers > Extension Attributes
#   Type: Script
#   Data Type: String
# ============================================================

INSTALLED_VERSION=$(stratium-hooks version 2>/dev/null | awk '{print $2}' || echo "not_installed")
echo "<result>${INSTALLED_VERSION}</result>"
