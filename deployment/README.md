[Provider](https://github.com/oceanprotocol/provider) has the following dependencies:
- [Aquarius](https://github.com/oceanprotocol/aquarius) 
- Ethereum network

which means these components must be available before the deployment.

The following template could be customized based on environment's specifics:
[provider-standard-networks-deployment-example.yaml](https://github.com/oceanprotocol/provider/blob/deployment_files/deployment/provider-standard-networks-deployment-example.yaml)

Tip: before deployment you can [validate](https://github.com/instrumenta/kubeval) the yaml file.

```
kubectl config set-context --current --namespace ocean
kubectl apply -f provider-deploy.yaml
deployment.apps/provider created

kubectl get pod -l app=provider
NAME                        READY   STATUS    RESTARTS   AGE
provider-764ffbdb59-bgmnl   1/1     Running   0          55s
```




