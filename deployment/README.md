

- [Kubernetes deployment](#kubernetes-deployment)
- [Docker Compose deployment](#docker-compose-deployment)


#### Kubernetes deployment

[Provider](https://github.com/oceanprotocol/provider) has the following dependencies:

- [Aquarius](https://github.com/oceanprotocol/aquarius)
- Ethereum network

which means these components must be available before the deployment.

In this example we will  run Provider as kubernetes deployment resource.

Additional parameters could be [added](https://github.com/oceanprotocol/provider) and the template could be adjusted based on these considerations.
One common case is the deployment for one of the following Ethereum networks:

- mainnet
- rinkeby
- ropsten

and the following template (annotated) could be edited and used for deployment.

*provider-standard-networks-deployment-example* deployment (annotated)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: provider
  name: provider
spec:
  progressDeadlineSeconds: 60
  replicas: 1
  revisionHistoryLimit: 5
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
        - name: NETWORK_URL
          value: < mainnet, rinkeby, ropsten or custom Openethereum service >
        - name: PROVIDER_PRIVATE_KEY
          value: < private key>
        - name: LOG_LEVEL
          value: INFO
        - name: OCEAN_PROVIDER_URL
          value: http://0.0.0.0:8030
        - name: OCEAN_PROVIDER_WORKERS
          value: "1"
        - name: IPFS_GATEWAY
          value: < IPFS gateway if defined/available >
        - name: OCEAN_PROVIDER_TIMEOUT
          value: "9000"
        - name: AQUARIUS_URL
          value: < http://aquarius_url >
        image: oceanprotocol/provider-py:<check tag on hub.docker.com >
        imagePullPolicy: IfNotPresent
        name: provider
        ports:
        - containerPort: 8030
          protocol: TCP
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
provider-764ffbdb59-bgmnl   1/1     Running   0          55s
```



next step is to create a [service](https://kubernetes.io/docs/concepts/services-networking/service/) (eg. ClusterIP,  NodePort,  Loadbalancer, ExternalName) for this deployment depending on environment specs.



#### Docker Compose deployment



The following steps could be used as example to run Provider as docker container configured as service with systemd.

a) create */etc/docker/compose/provider/docker-compose.yml* file

*/etc/docker/compose/provider/docker-compose.yml* (annotated)

```yaml
version: '3'
services:
  provider:
    image: oceanprotocol/provider-py:latest ==> specificy version (check on https://hub.docker.com/r/oceanprotocol/provider-py )
    container_name: provider
    ports:
      - 8030:8030
    networks:
      backend:
    environment:
      NETWORK_URL: ropsten
      INFURA_PROJECT_ID: "< your INFURA project id"
      PROVIDER_PRIVATE_KEY: "< your private key >"
      LOG_LEVEL: DEBUG
      OCEAN_PROVIDER_URL: 'http://0.0.0.0:8030'
      OCEAN_PROVIDER_WORKERS: "1"
      IPFS_GATEWAY: "< your IPFS gateway >"
      OCEAN_PROVIDER_TIMEOUT: "9000"
      OPERATOR_SERVICE_URL: "https://nextv.operator.dev-ocean.com/" => (use custom value for Operator Service URL)
      AQUARIUS_URL: "http//localhost:5000" => (use custom value Aquarius URL)
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
   Loaded: loaded (/etc/systemd/system/docker-compose@provider.service; disabled; vendor preset: disabled)
   Active: active (exited) since Mon 2021-04-05 10:52:07 UTC; 5min ago
  Process: 31260 ExecStart=/usr/bin/env docker-compose -p $PROJECT up -d (code=exited, status=0/SUCCESS)
  Process: 31248 ExecStartPre=/usr/bin/env docker-compose -p $PROJECT pull (code=exited, status=0/SUCCESS)
 Main PID: 31260 (code=exited, status=0/SUCCESS)

Apr 05 10:52:05 ip-172-31-32-61.eu-central-1.compute.internal env[31248]: Pulling provider ...
Apr 05 10:52:06 ip-172-31-32-61.eu-central-1.compute.internal env[31248]: Pulling provider ... pulling from oceanprotocol/provid...
Apr 05 10:52:06 ip-172-31-32-61.eu-central-1.compute.internal env[31248]: Pulling provider ... digest: sha256:2bfd5e4c1d00469d70...
Apr 05 10:52:06 ip-172-31-32-61.eu-central-1.compute.internal env[31248]: Pulling provider ... status: image is up to date for o...
Apr 05 10:52:06 ip-172-31-32-61.eu-central-1.compute.internal env[31248]: Pulling provider ... done
Apr 05 10:52:07 ip-172-31-32-61.eu-central-1.compute.internal env[31260]: Building with native build. Learn about native build in Compose here: https://docs.docker.com/go/compose-native-build/
Apr 05 10:52:07 ip-172-31-32-61.eu-central-1.compute.internal env[31260]: Starting ocean_provider_1 ...
Apr 05 10:52:07 ip-172-31-32-61.eu-central-1.compute.internal env[31260]: Starting ocean_provider_1 ... done
Apr 05 10:52:07 ip-172-31-32-61.eu-central-1.compute.internal systemd[1]: Started provider service with docker compose.
Hint: Some lines were ellipsized, use -l to show in full.
```



confirm provider service is accessible on localhost port 8030/tcp:

```shell
$ curl localhost:8030
{"computeAddress":null,"network-url":"ropsten","providerAddress":"0xe08A1dAe983BC701D05E492DB80e0144f8f4b909","serviceEndpoints":{"computeDelete":["DELETE","/api/v1/services/compute"],"computeStart":["POST","/api/v1/services/compute"],"computeStatus":["GET","/api/v1/services/compute"],"computeStop":["PUT","/api/v1/services/compute"],"download":["GET","/api/v1/services/download"],"encrypt":["POST","/api/v1/services/encrypt"],"fileinfo":["POST","/api/v1/services/fileinfo"],"initialize":["GET","/api/v1/services/initialize"],"nonce":["GET","/api/v1/services/nonce"]},"software":"Provider","version":"0.4.8"}

```



If needed, use docker cli to check provider service logs:

== identify container id

```shell
$ docker ps
CONTAINER ID   IMAGE                              COMMAND                  CREATED          STATUS          PORTS                              NAMES
e8aa7813ce76   oceanprotocol/provider-py:latest   "/ocean-provider/doc…"   19 seconds ago   Up 19 seconds   0.0.0.0:8030->8030/tcp             provider

```



== check logs from provider docker container

```shell
$ docker logs --follow e8aa7813ce76
[2021-04-05 11:06:56 +0000] [10] [INFO] Starting gunicorn 20.0.4
[2021-04-05 11:06:56 +0000] [10] [INFO] Listening at: http://0.0.0.0:8030 (10)
[2021-04-05 11:06:56 +0000] [10] [INFO] Using worker: sync
[2021-04-05 11:06:56 +0000] [12] [INFO] Booting worker with pid: 12
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: loading config file /ocean-provider/config.ini
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ network = ropsten
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ artifacts.path = /ocean-contracts/artifacts
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ aquarius.url = http//localhost:5000
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ operator_service.url = https://nextv.operator.dev-ocean.com/
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ allow_non_public_ip = False
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: loading config file /ocean-provider/config.ini
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ network = ropsten
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ artifacts.path = /ocean-contracts/artifacts
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ aquarius.url = http//localhost:5000
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ operator_service.url = https://nextv.operator.dev-ocean.com/
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ allow_non_public_ip = False
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: loading config file /ocean-provider/config.ini
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ network = ropsten
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ artifacts.path = /ocean-contracts/artifacts
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ aquarius.url = http//localhost:5000
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ operator_service.url = https://nextv.operator.dev-ocean.com/
2021-04-05 11:06:57 e8aa7813ce76 config[12] DEBUG Config: setting environ allow_non_public_ip = False
```

