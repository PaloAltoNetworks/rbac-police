#!/usr/bin/env python3
import os
from sys import argv
import regex

POLICY_DIR = "../../lib"
EXCLUDED_DIRS = ["ignore", "utils"]

# Prints documentation for the policies in POLICY_DIR
def main():
    docs = "## Policy Library\n"
    policy_paths = []

    # Get paths to all policies
    for root, dirs, files in os.walk(POLICY_DIR, topdown=True):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file_name in files:
            if file_name.endswith(".rego"):
                policy_paths.append(os.path.join(root, file_name))
    
    # Generate documentation for each policy
    for policy_path in sorted(policy_paths):            
        docs += generate_doc(policy_path)
    
    # Output results
    print(docs)

"""
Returns the description, severity and violation types of the
policy at @policy_path, in the following markdown format:

### [<policy_name>](../lib/<policy_name>.rego)
- Description: `<description>`
- Severity: `<severity>`
- Violation types: `<violation_types>`
"""
def generate_doc(policy_path):
    policy_name = os.path.basename(policy_path)[:-5] # remove ".rego"
    policy_path_from_docs_dir = policy_path[3:] # remove "../"
    doc = f"### [{policy_name}]({policy_path_from_docs_dir})\n"

    violtaion_types = []
    description, severity = "", ""
    with open(policy_path, "r")  as policy_file:
        for line in policy_file.readlines():
            if defined_in_rego_line_as_true(line, "checkServiceAccounts"):
                violtaion_types.append("serviceAccounts")
            elif defined_in_rego_line_as_true(line, "checkNodes"):
                violtaion_types.append("nodes")
            elif defined_in_rego_line_as_true(line, "checkCombined"):
                violtaion_types.append("combined")
            elif defined_in_rego_line(line, "desc"):
                if "concat(\", \"" in line:
                    description = "".join(line.split("\"")[1:-3])
                    description = description.replace("namespaces (%v)", "namespaces")
                else:
                    description = "".join(line.split("\"")[1:-1])
            elif defined_in_rego_line(line, "severity"):
                severity = "".join(line.split("\"")[1:-1])
    
    if len(violtaion_types) == 0 and policy_name == "providerIAM":
        violtaion_types.append("serviceAccounts")

    doc += f"- Description: `{description}`\n"
    doc += f"- Severity: `{severity}`\n"
    doc += f"- Violation types: `{', '.join(sorted(violtaion_types, reverse=True))}`\n"
    return doc

# Returns True if @variable is defined in @line
def defined_in_rego_line(line, variable):
    return regex.match(f"\s*{variable}\s*:?=", line) != None
 
# Returns True if @variable is defined as 'true' in @line
def defined_in_rego_line_as_true(line, variable):
    return regex.match(f"\s*{variable}\s*:?=\s*true", line) != None


if __name__ == "__main__":
    main()
