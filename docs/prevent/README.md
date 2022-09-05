# Prevent K8s PrivEsc via Admission policies
Attacks that misuse powerful permisions often diverage from common usage of such permissions. K8s defenders can capitilize on that to identify compromised credentials and prevent attacks in real-time via admission controler. This directory contains several example policies for OPA Gatekeeper.

## Suspicious SelfSubjectReviews
A common attacker pattern following credential theft is querying the system for their permissions. In Kubernetes, that is done via the SelfSubjectAccessReview or SelfSubjectRulesReview APIs. Non-human identities like serviceAccounts and nodes querying these APIs for their permissions are strong indicators of compromise.

## Suspicious Assignment of Controller Service Accounts
By default, the kube-system namespace hosts several admin-equivalent service accounts that are used by controllers running as part of the api-server. Attackers that can create pods or pod controllers in the kube-system namespace, or modify pod controllers in kube-system namespace, can assign one of these admin-equivalent service accounts to a pod in their control and abuse their powerful token to gain complete control over the cluster. 

Controller service accounts aren't normally assigned to running pods. Defenders can capitalize on that to detect this privilege escalation attack with a policy that alerts on requests that attach a controller service account to an existing or new kube-system pod.


