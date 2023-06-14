- [Kubernetes deployment](#kubernetes-deployment)
- [Docker Compose deployment](#docker-compose-deployment)


#### Kubernetes deployment

[Provider](https://github.com/oceanprotocol/provider) has the following dependencies:

- [Aquarius](https://github.com/oceanprotocol/aquarius)
- Blockchain network(s) RPC access

which means these components must be available before the deployment.

In this example we will  run Provider as kubernetes deployment resource.

Additional parameters could be [added](https://github.com/oceanprotocol/provider) and the template could be adjusted based on these considerations.
One common case is the deployment for the following test networks:

- goerli
- mumbai

and the following template (annotated) could be edited and used for deployment.

Note: in the following examples `"5"` and `"80001"` are the chain ids for `goerli` and `mumbai` test networks.

*provider-standard-networks-deployment-example* deployment (annotated)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: provider
  name: provider
spec:
  progressDeadlineSeconds: 2147483647
  replicas: 1
  revisionHistoryLimit: 2147483647
  selector:
    matchLabels:
      app: provider
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: provider
    spec:
      containers:
      - env:
        - name: ARTIFACTS_PATH
          value: /ocean-provider/artifacts
        - name: NETWORK_URL
          value: |
            {"5":"https://goerli.infura.io/v3/<your INFURA project id","80001":"https://polygon-mumbai.infura.io/v3/<your INFURA project id"}
        - name: PROVIDER_PRIVATE_KEY
          value: |
            {"5":"<your private key>","80001":"<your private key>"}
        - name: LOG_LEVEL
          value: DEBUG
        - name: OCEAN_PROVIDER_URL
          value: http://0.0.0.0:8030
        - name: OCEAN_PROVIDER_WORKERS
          value: "4"
        - name: IPFS_GATEWAY
          value: < your IPFS gateway >
        - name: OCEAN_PROVIDER_TIMEOUT
          value: "9000"
        - name: OPERATOR_SERVICE_URL
          value: < Operator service URL>
        - name: AQUARIUS_URL
          value: < Aquarius URL >
        - name: UNIVERSAL_PRIVATE_KEY
          value: <your universal private key>
        - name: REQUEST_TIMEOUT
          value: "10"
        image: oceanprotocol/provider-py:latest => (check on https://hub.docker.com/r/oceanprotocol/provider-py for specific tag)
        imagePullPolicy: Always
        name: provider
        ports:
        - containerPort: 8030
          protocol: TCP
        resources:
          limits:
            cpu: 500m
            memory: 700Mi
          requests:
            cpu: 500m
            memory: 700Mi
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      terminationGracePeriodSeconds: 30
```



Tip: before deployment you can [validate](https://github.com/instrumenta/kubeval) the yaml file.

```shell
kubectl config set-context --current --namespace ocean
kubectl apply -f provider-deploy.yaml
deployment.apps/provider created

kubectl get pod -l app=provider
NAME                        READY   STATUS    RESTARTS   AGE
provider-865cb8cf9d-r9xm4   1/1     Running   0          67s
```



next step is to create a [service](https://kubernetes.io/docs/concepts/services-networking/service/) (eg. ClusterIP,  NodePort,  Loadbalancer, ExternalName) for this deployment depending on environment specs.



#### Docker Compose deployment



The following steps could be used as example to run Provider as docker container configured as service with systemd.

Note: in the following examples `"5"` and `"80001"` are the chain ids for `goerli` and `mumbai` test networks.

a) create */etc/docker/compose/provider/docker-compose.yml* file

*/etc/docker/compose/provider/docker-compose.yml* (annotated)

```yaml
version: '3'
services:
  provider:
    image: oceanprotocol/provider-py:latest =>(check on https://hub.docker.com/r/oceanprotocol/provider-py for specific tag)
    container_name: provider
    restart: on-failure
    ports:
      - 8030:8030
    networks:
      backend:
    environment:
      ARTIFACTS_PATH: "/ocean-contracts/artifacts"
      NETWORK_URL: '{"5":"https://goerli.infura.io/v3/<your INFURA project id>","80001":"https://polygon-mumbai.infura.io/v3/<your INFURA project id>"}'
      PROVIDER_PRIVATE_KEY: '{"5":"<your private key>","80001":"<your private key"}'
      LOG_LEVEL: DEBUG
      OCEAN_PROVIDER_URL: 'http://0.0.0.0:8030'
      OCEAN_PROVIDER_WORKERS: "1"
      IPFS_GATEWAY: "< your IPFS gateway >"
      OCEAN_PROVIDER_TIMEOUT: "9000"
      OPERATOR_SERVICE_URL: "https://stagev4.c2d.oceanprotocol.com" => (use custom value for Operator Service URL)
      AQUARIUS_URL: "http//localhost:5000" => (use custom value Aquarius URL)
      REQUEST_TIMEOUT: "10"
networks:
  backend:
    driver: bridge
```



b) create */etc/systemd/system/docker-compose@provider.service* file

 */etc/systemd/system/docker-compose@provider.service* (this example file could be customized)

```shell
[Unit]
Description=%i service with docker compose
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=true
Environment="PROJECT=ocean"
WorkingDirectory=/etc/docker/compose/%i
ExecStartPre=/usr/bin/env docker-compose -p $PROJECT pull
ExecStart=/usr/bin/env docker-compose -p $PROJECT up -d
ExecStop=/usr/bin/env docker-compose -p $PROJECT stop


[Install]
WantedBy=multi-user.target
```



c) run:

```shell
$ sudo systemctl daemon-reload
```

optional - enable services to start at boot:

```shell
$ sudo systemctl enable docker-compose@provider.service
```



d) start provider service:

```shell
$ sudo systemctl start docker-compose@provider.service
```



check status:

```shell
$ sudo systemctl status docker-compose@provider.service
● docker-compose@provider.service - provider service with docker compose
     Loaded: loaded (/etc/systemd/system/docker-compose@provider.service; disabled; vendor preset: enabled)
     Active: active (exited) since Wed 2023-06-14 09:41:53 UTC; 20s ago
    Process: 4118 ExecStartPre=/usr/bin/env docker-compose -p $PROJECT pull (code=exited, status=0/SUCCESS)
    Process: 4126 ExecStart=/usr/bin/env docker-compose -p $PROJECT up -d (code=exited, status=0/SUCCESS)
   Main PID: 4126 (code=exited, status=0/SUCCESS)
        CPU: 93ms

Jun 14 09:41:52 testvm systemd[1]: Starting provider service with docker compose...
Jun 14 09:41:52 testvm env[4118]:  provider Pulling
Jun 14 09:41:53 testvm env[4118]:  provider Pulled
Jun 14 09:41:53 testvm env[4126]:  Container provider  Created
Jun 14 09:41:53 testvm env[4126]:  Container provider  Starting
Jun 14 09:41:53 testvm env[4126]:  Container provider  Started
Jun 14 09:41:53 testvm systemd[1]: Finished provider service with docker compose.
```



confirm provider service is accessible on `localhost` port 8030/tcp:

```shell
$ curl localhost:8030
{"chainIds":[5,80001],"providerAddresses":{"5":"0x00c6A0BC5cD0078d6Cd0b659E8061B404cfa5704","80001":"0x4256Df50c94D9a7e04610976cde01aED91eB531E"},"serviceEndpoints":{"computeDelete":["DELETE","/api/services/compute"],"computeEnvironments":["GET","/api/services/computeEnvironments"],"computeResult":["GET","/api/services/computeResult"],"computeStart":["POST","/api/services/compute"],"computeStatus":["GET","/api/services/compute"],"computeStop":["PUT","/api/services/compute"],"create_auth_token":["GET","/api/services/createAuthToken"],"decrypt":["POST","/api/services/decrypt"],"delete_auth_token":["DELETE","/api/services/deleteAuthToken"],"download":["GET","/api/services/download"],"encrypt":["POST","/api/services/encrypt"],"fileinfo":["POST","/api/services/fileinfo"],"initialize":["GET","/api/services/initialize"],"initializeCompute":["POST","/api/services/initializeCompute"],"nonce":["GET","/api/services/nonce"],"validateContainer":["POST","/api/services/validateContainer"]},"software":"Provider","version":"2.0.2"}
```



If needed, use docker cli to check provider service logs:

- identify container id:

```shell
$ docker ps
CONTAINER ID   IMAGE                              COMMAND                  CREATED          STATUS              PORTS                                       NAMES
594415b13f8c   oceanprotocol/provider-py:v2.0.2   "/ocean-provider/doc…"   12 minutes ago   Up About a minute   0.0.0.0:8030->8030/tcp, :::8030->8030/tcp   provider

```



- check logs from provider docker container:

```shell
$ docker logs --follow provider
[2023-06-14 09:31:02 +0000] [8] [INFO] Starting gunicorn 20.0.4
[2023-06-14 09:31:02 +0000] [8] [INFO] Listening at: http://0.0.0.0:8030 (8)
[2023-06-14 09:31:02 +0000] [8] [INFO] Using worker: sync
[2023-06-14 09:31:02 +0000] [10] [INFO] Booting worker with pid: 10
2023-06-14 09:31:02 594415b13f8c rlp.codec[10] DEBUG Consider installing rusty-rlp to improve pyrlp performance with a rust based backend
2023-06-14 09:31:12 594415b13f8c ocean_provider.run[10] INFO incoming request = http, GET, 172.18.0.1, /?
2023-06-14 09:31:12 594415b13f8c ocean_provider.run[10] INFO root endpoint called
2023-06-14 09:31:12 594415b13f8c ocean_provider.run[10] INFO root endpoint response = <Response 1031 bytes [200 OK]>
[2023-06-14 09:41:53 +0000] [8] [INFO] Starting gunicorn 20.0.4
[2023-06-14 09:41:53 +0000] [8] [INFO] Listening at: http://0.0.0.0:8030 (8)
[2023-06-14 09:41:53 +0000] [8] [INFO] Using worker: sync
[2023-06-14 09:41:53 +0000] [10] [INFO] Booting worker with pid: 10
2023-06-14 09:41:54 594415b13f8c rlp.codec[10] DEBUG Consider installing rusty-rlp to improve pyrlp performance with a rust based backend
2023-06-14 09:42:40 594415b13f8c ocean_provider.run[10] INFO incoming request = http, GET, 172.18.0.1, /?
2023-06-14 09:42:40 594415b13f8c ocean_provider.run[10] INFO root endpoint called
2023-06-14 09:42:40 594415b13f8c ocean_provider.run[10] INFO root endpoint response = <Response 1031 bytes [200 OK]>

```
