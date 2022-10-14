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


Q&A
---

### Why not use the [official Kong JWT plugin](https://docs.konghq.com/hub/kong-inc/jwt/)?

That plugin is for generating your own JWTs signed by Kong. We need to validate JWTs signed by external entities like firebase.
