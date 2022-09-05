#!/bin/bash
set -e 

# Generate dir name as "local_<cluster-name>_<date>_<random-str>"
curr_context=$(kubectl config current-context)
curr_context="${curr_context//[[:space:]]/}" # no whitespace
suffix="local_${curr_context:0:15}_$(date +%Y%b%d)" # truncate curr_context at 15 chars
# Find a non-existing dir name
dir="${suffix}_$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 4)"
while [ -d "$dir" ] ; do
    dir="${suffix}_$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 4)"
done
mkdir "$dir"

# Populate dir
# Mandatory:
kubectl get pods -A -o json > "$dir/pods.json"
kubectl get nodes -A -o json > "$dir/nodes.json"
kubectl get serviceaccounts -A -o json > "$dir/serviceaccounts.json"
kubectl get roles -A -o json > "$dir/roles.json"
kubectl get rolebindings -A -o json > "$dir/rolebindings.json"
kubectl get clusterroles -o json > "$dir/clusterroles.json"
kubectl get clusterrolebindings -o json > "$dir/clusterrolebindings.json"
# Optional:
kubectl config view -o jsonpath='{.contexts[?(@.name == "'"${curr_context}"'")].context.cluster}' > "$dir/cluster_name"
kubectl get --raw /version > "$dir/version.json"

echo "[+] Cluster data at $dir"

