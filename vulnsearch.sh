#!/bin/bash

# This script runs specified Python scripts (tools) in the /scripts/ folder,
# passing the `--patterns` and `--directory` arguments to each script.

# Function to display usage instructions
usage() {
  echo "Usage: $0 --patterns PATTERN [--tools INDEXES] [--directory DIRECTORY]"
  echo "  --patterns PATTERN    The pattern to pass to the scripts."
  echo "  --tools INDEXES       (Optional) Comma-separated list of tool indices to run."
  echo "                        Indices start from 1 and correspond to the order of scripts found."
  echo "  --directory DIRECTORY (Optional) Directory to scan for PHP files."
  exit 1
}

# Initialize variables
PATTERNS=""
DIRECTORY=""
SELECTED_TOOLS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --patterns)
      PATTERNS=$2
      shift 2
      ;;
    --tools)
      IFS=',' read -r -a SELECTED_TOOLS <<< "$2"
      shift 2
      ;;
    --directory)
      DIRECTORY=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

# Check if patterns argument is provided
if [ -z "$PATTERNS" ]; then
  usage
fi

# Directory containing the Python scripts
SCRIPTS_DIR="./scripts"

# Find all .py files in the specified directory and store them in the SCRIPTS array
SCRIPTS=($(find "$SCRIPTS_DIR" -maxdepth 1 -name "*.py"))

# If SELECTED_TOOLS is empty, run all scripts
if [ ${#SELECTED_TOOLS[@]} -eq 0 ]; then
  for (( i=0; i<${#SCRIPTS[@]}; i++ )); do
    SELECTED_TOOLS+=("$((i+1))")
  done
fi

# Loop through each specified tool and execute it with the provided patterns and directory
for INDEX in "${SELECTED_TOOLS[@]}"; do
  SCRIPT_INDEX=$((INDEX-1))
  if [ -n "${SCRIPTS[$SCRIPT_INDEX]}" ] && [ -f "${SCRIPTS[$SCRIPT_INDEX]}" ]; then
    echo "Running ${SCRIPTS[$SCRIPT_INDEX]}"
    if [ -n "$DIRECTORY" ]; then
      python3 "${SCRIPTS[$SCRIPT_INDEX]}" --patterns "$PATTERNS" --directory "$DIRECTORY"
    else
      python3 "${SCRIPTS[$SCRIPT_INDEX]}" --patterns "$PATTERNS"
    fi
  else
    echo "Warning: Tool index $INDEX does not exist or file not found. Skipping."
  fi
done