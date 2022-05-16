#!/bin/bash
# Updates the policy library doc at policies.md
set -e 

policy_doc_file="../policies.md"
if [ ! -f "$policy_doc_file" ]; then
    echo "[!] Please run this script from <rbac-police>/docs/utils"
    exit 1
fi

policy_lib_line="## Policy Library"

# Get policy doc without the policy library part
policy_doc_without_lib=$(grep -B 99999 "$policy_lib_line" $policy_doc_file | grep -v "$policy_lib_line")
# Generate updated policy library
new_policy_lib=$(./generate_policylib_docs.py)

# Rebuild policies.md with updated policy library
echo "$policy_doc_without_lib" > $policy_doc_file
echo >> $policy_doc_file
echo "$new_policy_lib" >> $policy_doc_file

