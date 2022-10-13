# Prevent K8s PrivEsc Attacks With Admission Control
Attacks that misuse powerful permissions often diverge from the credentials' common usage. K8s defenders can capitalize on that to identify compromised credentials and prevent attacks in real-time via admission control. This directory contains several example policies for OPA Gatekeeper.

## [Suspicious SelfSubjectReviews](./suspicious_self_subject_review)
A common attack pattern following credential theft is querying for their permissions. In Kubernetes, that is done via the SelfSubjectAccessReview or SelfSubjectRulesReview APIs. Non-human identities such as service accounts or nodes querying these APIs for their permissions are strong indicators of compromise.

## [Suspicious Assignment of Controller Service Accounts](./suspicious_assignment_of_controller_service_accounts)
By default, the kube-system namespace hosts several admin-equivalent service accounts used by controllers running as part of the api-server. Attackers that can create pods or pod controllers in the kube-system namespace, or modify pod controllers in kube-system namespace, can assign one of these admin-equivalent service accounts to a pod in their control to gain a an admin-equivalent service account token and abuse it to take over the entire cluster.

Controller service accounts aren't normally assigned to running pods. Defenders can capitalize on that to detect this privilege escalation attack with a policy that alerts on requests that attach a controller service account to an existing or new kube-system pod.


