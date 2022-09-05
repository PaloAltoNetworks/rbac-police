#!/bin/bash
# Updates the policy library doc at policies.md
set -e 

policy_doc_file="docs/policies.md"
generate_policy_doc_script="utils/generate_policylib_docs.py"
if [ ! -f "$policy_doc_file" ]; then
  # Not in root dir, try from utils dir
  policy_doc_file="../docs/policies.md"
  generate_policy_doc_script="./generate_policylib_docs.py"
  if [ ! -f "$policy_doc_file" ]; then
    echo "[!] Please run this script from rbac-police's root directory"
    exit 1
  fi
fi

policy_lib_line="## Policy Library"

# Get policy doc without the policy library part
policy_doc_without_lib=$(grep -B 99999 "$policy_lib_line" $policy_doc_file | grep -v "$policy_lib_line")
# Generate updated policy library
new_policy_lib=$($generate_policy_doc_script)

# Rebuild policies.md with updated policy library
echo "$policy_doc_without_lib" > $policy_doc_file
echo >> $policy_doc_file
echo "$new_policy_lib" >> $policy_doc_file

