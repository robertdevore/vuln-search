#!/bin/bash

# This script runs specified Python scripts (tools) in the /scripts/ folder,
# passing the `--patterns` and `--directory` arguments to each script.

# Function to display usage instructions
usage() {
  echo "Usage: $0 --directory DIRECTORY [--patterns PATTERN] [--tools INDEXES]"
  echo "  --directory DIRECTORY (Required) Directory to scan for PHP files."
  echo "  --patterns  PATTERN   (Optional) The pattern to pass to the scripts. Default is 'all'."
  echo "  --tools     INDEXES   (Optional) Comma-separated list of tool indices to run."
  echo "                        Indices start from 1 and correspond to the order of scripts found."
  exit 1
}

# Initialize variables
PATTERNS="all"  # Default pattern
DIRECTORY=""
SELECTED_TOOLS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --patterns)
      PATTERNS=$2
      shift 2
      ;;
    --directory)
      DIRECTORY=$2
      shift 2
      ;;
    --tools)
      IFS=',' read -r -a SELECTED_TOOLS <<< "$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

# Check if directory argument is provided
if [ -z "$DIRECTORY" ]; then
  echo "Error: --directory option is required."
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

# Record the start time
start_time=$(date +%s)

# Loop through each specified tool and execute it with the provided patterns and directory
for INDEX in "${SELECTED_TOOLS[@]}"; do
  SCRIPT_INDEX=$((INDEX-1))
  if [ -n "${SCRIPTS[$SCRIPT_INDEX]}" ] && [ -f "${SCRIPTS[$SCRIPT_INDEX]}" ]; then
    echo -e "\n[*] Running ${SCRIPTS[$SCRIPT_INDEX]}"
    if [ -n "$PATTERNS" ]; then
      python3 "${SCRIPTS[$SCRIPT_INDEX]}" --patterns "$PATTERNS" --directory "$DIRECTORY"
    else
      python3 "${SCRIPTS[$SCRIPT_INDEX]}" --directory "$DIRECTORY"
    fi
  else
    echo "Warning: Tool index $INDEX does not exist or file not found. Skipping."
  fi
done

# Record the end time
end_time=$(date +%s)

# Calculate and display the total elapsed time
elapsed_time=$((end_time - start_time))
echo -e "\nTotal execution time: ${elapsed_time} seconds"
