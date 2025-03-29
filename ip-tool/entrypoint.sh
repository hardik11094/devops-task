#!/bin/bash
set -x
set -e
set -o errexit
set -o pipefail
 
# Function to run in collection mode
run_collection_mode() {
    echo "Running in collection mode..."
    ip-tool --check-collision "${OUTPUT_FILE}"
}
 
# Function to run in collision check mode
run_collision_check_mode() {
    echo "Running in collision check mode..."
    if [ ! -f "${OUTPUT_FILE}" ]; then
        echo "Error: Output file ${OUTPUT_FILE} not found!" >&2
        exit 1
    fi
    ip-tool --check-collision "${OUTPUT_FILE}"
}
 
# Function to run in default mode
run_default_mode() {
    echo "Running in default mode (report local IP networks)..."
    exec ip-tool
}
 
# Determine mode and execute appropriate function
case "${MODE}" in
    "collection")
        run_collection_mode
        ;;
    "check")
        run_collision_check_mode
        ;;
    *)
        run_default_mode
        ;;
esac