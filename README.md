Kong Remote JWT Plugin
======================

This is a custom plugin for validating JWTs issued by an external service whose signing certificates are available in a PEM format via http. Common examples would be JWTs issued by [Firebase](https://firebase.google.com/) or [Pub/Sub authenticated push subscriptions](https://cloud.google.com/pubsub/docs/push#authentication).

Setup
-----

### Install

To use this plugin, you will need to install it, configure a nginx shared dictionary, configure this plugin, and add it to your desired services/routes.

For installing the plugin, you can use luarocks. Example:

```sh
luarocks install https://raw.githubusercontent.com/harmonicai/kong-remote-jwt-auth/master/kong-plugin-remote-jwt-auth-dev-1.rockspec
```

A minimal example `Dockerfile` containing this would be:
```
FROM kong:3.0
USER root
RUN apk add --no-cache gcc musl-dev
RUN luarocks install https://raw.githubusercontent.com/harmonicai/kong-remote-jwt-auth/master/kong-plugin-remote-jwt-auth-dev-1.rockspec
USER kong
```

### Configure nginx shared dictionary

This plugin relies on a shared dictionary to sync certificates across nginx workers. The directive for this must be injected into kong's nginx.conf. If you are running kong in docker/docker-compose then you can inject it with an environment variable:
```
KONG_NGINX_HTTP_LUA_SHARED_DICT: remote_jwt_auth 1m
```

If you are running kong in kubernetes via the helm chart, then in the `env:` section you can add:
```
env:
  nginx_http_lua_shared_dict: remote_jwt_auth 1m
```

In both of these example, we allocate 1 megabyte to the shared dictionary. This should be plenty for firebase/pubsub which each only expose 2 certificates at a time but you may need to adjust the size of this cache if you need to handle many certificates.

### Configure the plugin

We need to tell kong to load the plugin. In docker/docker-compose this can be configured with environment variables:
```
KONG_PLUGINS: bundled, remote-jwt-auth
```

In kubernetes via the helm chart, it can be added to the `env:` section:
```
env:
  plugins: bundled, remote-jwt-auth
```

Then we need to configure the plugin itself. An example config for `kong.yaml` is:
```
_format_version: "3.0"

services:
  - name: foo
    url: http://foo:80
    routes:
      - name: foo
        paths:
          - /
    plugins:
      - name: remote-jwt-auth
        config:
          authenticated_consumer: authenticated-firebase
          signing_urls:
            - "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
          claims_to_verify:
            - name: iss
              allowed_values:
                - "https://securetoken.google.com/google-project-id-here"
            - name: aud
              allowed_values:
                - "google-project-id-here"
          jwt_service_url: http://midtier-api.default.svc.cluster.local./auth/auth_jwt
          jwt_service_timeout: 5000
          jwt_service_retries: 3
          jwt_service_retry_base_delay: 100
consumers:
  - username: authenticated-firebase
```

In kubernetes, an example config would be:
```
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: remote-jwt-auth
  namespace: default
config:
  anonymous: anonymous
  authenticated_consumer: authenticated-firebase
  signing_urls:
    - "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  claims_to_verify:
    - name: iss
      allowed_values:
        - "https://securetoken.google.com/google-project-id-here"
    - name: aud
      allowed_values:
plugin: remote-jwt-auth
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: firebase-test
  namespace: default
  annotations:
    kubernetes.io/ingress.class: kong
    konghq.com/plugins: remote-jwt-auth
    # Redirect http to https:
    konghq.com/protocols: https
    konghq.com/https-redirect-status-code: "302"
    # cert-manager
    kubernetes.io/tls-acme: "true"
    cert-manager.io/cluster-issuer: letsencrypt-dns-production
spec:
  tls:
    - secretName: firebasetest-cert
      hosts:
        - firebasetest.foo.bar
  rules:
    - host: firebasetest.foo.bar
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: firebasetest-service
                port:
                  name: http
```


Release Process
---------------

To release a new version of the plugin:

1. **Create a new release branch and rockspec** in this repository by running the [Release Kong Plugin](https://github.com/harmonicai/kong-remote-jwt-auth/actions/workflows/release.yml) GitHub action. Manually increment the release version in the "Run workflow" dropdown.

2. **Build a new Kong Docker image** with the updated plugin by running the [Build Kong Docker Image with Auth Plugin](https://github.com/harmonicai/backend/actions/workflows/kong_docker_build.yml) GitHub action in the backend repository. Specify the plugin branch version from step 1 in the "Run workflow" dropdown.

3. **Update the Kong image tag** in the kubernetes repository configs and publish PRs. Deploy to dev/canary first and test before deploying to production.

   Files to update:
   - `flux/dev/kong/01_kong.yaml`
   - `flux/canary/kong/01_kong.yaml`
   - `flux/prd/kong/01_kong.yaml`

   Example change:
   ```yaml
   image:
     repository: gcr.io/innate-empire-283902/github.com/harmonicai/backend/kong/prd
     tag: "v2.0.1"  # Update this to the new version, e.g., "v2.0.3"
   ```

4. **Monitor the release** after merging PRs. Use the following resources to verify the deployment:

   #### Dev Environment

   - [GCP Artifact Registry (dev)](https://console.cloud.google.com/artifacts/docker/innate-empire-283902/us/gcr.io/github.com%2Fharmonicai%2Fbackend%2Fkong%2Fdev?project=innate-empire-283902)
   - [k8s dev kong-kong deployment](https://console.cloud.google.com/kubernetes/deployment/us-central1/dev-cluster/kong/kong-kong/overview?project=innate-empire-283902)

   ```sh
   # Verify Flux reconciliation not failing
   kubectl get kustomization -n flux
   ```

   #### Canary Environment

   - [GCP Artifact Registry (prd)](https://console.cloud.google.com/artifacts/docker/innate-empire-283902/us/gcr.io/github.com%2Fharmonicai%2Fbackend%2Fkong%2Fprd?project=innate-empire-283902)
   - [k8s canary kong-canary-kong deployment](https://console.cloud.google.com/kubernetes/deployment/us-central1/prd-cluster/kong-canary/kong-canary-kong/overview?project=innate-empire-283902)

   ```sh
   # Watch the GitRepository update
   kubectl get gitrepository kong-canary -n kong-canary -w

   # Watch the HelmChart build (name is based on name + namespace)
   kubectl get helmchart kong-canary-kong-canary -n kong-canary -w

   # Watch the HelmRelease deploy
   kubectl get helmrelease kong-canary -n kong-canary -w

   # Check pods rolling out
   kubectl get pods -n kong-canary -w

   # Check logs for errors
   kubectl logs -n kong-canary -l app.kubernetes.io/instance=kong-canary -c proxy --tail=500 | grep -iE "error|warn|fail" | tail -30

   # If "log_level: debug" is set on the k8s config, the plugin will output debug logs
   kubectl logs -n kong-canary -l app.kubernetes.io/instance=kong-canary -c proxy -f | grep "remote-jwt-auth"
   ```

   #### Production Environment

   - [k8s prd kong-kong deployment](https://console.cloud.google.com/kubernetes/deployment/us-central1/prd-cluster/kong/kong-kong/overview?inv=1&invt=AbieBQ&project=innate-empire-283902)

   ```sh
   # Watch the GitRepository update
   kubectl get gitrepository kong -n kong -w

   # Watch the HelmChart build
   kubectl get helmchart kong-kong -n kong -w

   # Watch the HelmRelease deploy
   kubectl get helmrelease kong -n kong -w

   # Check pods rolling out
   kubectl get pods -n kong -w

   # Check logs for errors
   kubectl logs -n kong -l app.kubernetes.io/instance=kong -c proxy --tail=500 | grep -iE "error|warn|fail" | tail -30

   # If "log_level: debug" is set on the k8s config, the plugin will output debug logs
   kubectl logs -n kong -l app.kubernetes.io/instance=kong -c proxy -f | grep "remote-jwt-auth"
   ```


Q&A
---

### Why not use the [official Kong JWT plugin](https://docs.konghq.com/hub/kong-inc/jwt/)?

That plugin is for generating your own JWTs signed by Kong. We need to validate JWTs signed by external entities like firebase.
