#!/usr/bin/env python3
import os
from sys import argv
import regex

POLICY_DIR = "lib"
EXCLUDED_DIRS = ["ignore", "utils"]

# Prints documentation for the policies in POLICY_DIR
def main():
    # If needed, chdir to rbac-police's root directory
    cwd = os.getcwd()
    if cwd.endswith("utils") and not os.path.isdir(POLICY_DIR):
        os.chdir("..")

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
    policy_path_from_docs_dir = "../lib/" + policy_name
    doc = f"### [{policy_name}]({policy_path_from_docs_dir}.rego)\n"

    violation_types = []
    description, severity = "", ""
    with open(policy_path, "r")  as policy_file:
        for line in policy_file.readlines():
            if "targets" in line:
                if defined_in_rego_set(line, "targets", "serviceAccounts"):
                    violation_types.append("serviceAccounts")
                if defined_in_rego_set(line, "targets", "nodes"):
                    violation_types.append("nodes")
                if defined_in_rego_set(line, "targets", "combined"):
                    violation_types.append("combined")
                if defined_in_rego_set(line, "targets", "users"):
                    violation_types.append("users")
                if defined_in_rego_set(line, "targets", "groups"):
                    violation_types.append("groups")
            elif defined_in_rego_line(line, "desc"):
                if "concat(\", \"" in line:
                    description = "".join(line.split("\"")[1:-3])
                    description = description.replace("namespaces (%v)", "namespaces")
                else:
                    description = "".join(line.split("\"")[1:-1])
            elif defined_in_rego_line(line, "severity"):
                severity = "".join(line.split("\"")[1:-1])
    
    if len(violation_types) == 0 and policy_name == "providerIAM":
        violation_types.append("serviceAccounts")

    doc += f"- Description: `{description}`\n"
    doc += f"- Severity: `{severity}`\n"
    doc += f"- Violation types: `{', '.join(violation_types)}`\n"
    return doc

# Returns True if @variable is defined in @line
def defined_in_rego_line(line, variable):
    return regex.match(f"\s*{variable}\s*:?=", line) != None

# Returns True if @element is part of a set named @set_name defined in @line
def defined_in_rego_set(line, set_name, element):
     return regex.match(f'\s*{set_name}\s*:?=\s*\{{.*"{element}".*\}}', line) != None

if __name__ == "__main__":
    main()
