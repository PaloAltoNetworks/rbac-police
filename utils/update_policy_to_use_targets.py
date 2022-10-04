#!/usr/bin/env python3
# Updates a policy to use the new 'targets' set introduced in v1.1.0 instead of the old 'checkXXX' variables
# Usage: update_policy_to_use_targets.py <policy-file-path> <output-path>"
from sys import argv
import regex

def main(policy_path, output_path):
    updated_policy = []
    with open(policy_path, "r") as policy_file:
        targets = []
        line_to_insert_targets = -1

        # Iterate policy files
        for i, line in enumerate(policy_file):
            # Exit if policy is already in the new format
            if defined_as_rego_set(line, "targets"):
                print(f"[+] Policy '{policy_path}' already defines a 'targets' set, it's in the new format")
                return 
            # Add serviceAccounts to targets if checkServiceAccounts is defined
            elif defined_as_rego_true(line, "checkServiceAccounts"):
                if line_to_insert_targets < 0: 
                    line_to_insert_targets = i
                targets.append("serviceAccounts")
            # Add nodes to targets if checkNodes is defined
            elif defined_as_rego_true(line, "checkNodes"):
                if line_to_insert_targets < 0: 
                    line_to_insert_targets = i
                targets.append("nodes")    
            # Add combined to targets if checkCombined is defined
            elif defined_as_rego_true(line, "checkCombined"):
                if line_to_insert_targets < 0: 
                    line_to_insert_targets = i
                targets.append("combined")
            # Add all others lines to new policy
            else: 
                updated_policy.append(line) 
        # If couldn't find any checkXXX variable, exit
        if line_to_insert_targets == -1:
                print(f"[!] Policy '{policy_path}' doesn't seem like a wrapped rbac-police policy as it doesn't define a 'checkServiceAccounts', 'checkNodes' or 'checkCombined' variable")
                return
        # Inject the 'targets' set into the new policy
        targets_str = 'targets := {"' + '", "'.join(targets) + '"}\n'
        updated_policy.insert(line_to_insert_targets, targets_str)

        # Write updated policy to output_path
        with open(output_path, "w") as output_file:
            output_file.write("".join(updated_policy))
        print(f"[+] Done, new policy at {output_path}")

# Returns true if @set_name is defined as a Rego set in @line
def defined_as_rego_set(line, set_name):
    return regex.match(f'\s*{set_name}\s*:?=\s*\{{.*\}}', line) != None

# Returns true if @variable is a Rego variable set to true in @line
def defined_as_rego_true(line, variable):
    return regex.match(f'\s*{variable}\s*:?=\s*true', line) != None

if __name__ == "__main__":
    if len(argv) < 3:
        print(f"[+] Usage: {argv[0]} <policy-file-path> <output-path>")
        exit(1)
    policy_path = argv[1]
    output_path = argv[2]

    main(policy_path, output_path)
