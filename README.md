# WAF bouncer

Web application firewall using the appsec component from crowdsec.

It's meant to be used in front of an ingress/reverse proxy. The bouncer expects requests to be forwarded from the ingress and it will in turn forward requests to the crowdsec appsec component. The appsec component will make a decisions based on appsec rules and respond to the bouncer.

Example usage
* [Traefik](https://doc.traefik.io/traefik/middlewares/http/forwardauth)

### Important
The bouncer will reject all requests with 403 (forbidden) coming from an untrusted IP.

### Limitation
Due to a limitation in crowdsec, `MTLS` can't be used for authentication by itself and a crowdsec registered `APIKEY` must still be provided.

### CLI
```
Usage: waf-bouncer [OPTIONS]

Options:
      --listen-addr <LISTEN_ADDR>
          [env: LISTEN_ADDR=] [default: 127.0.0.1:3000]
      --trusted-proxies <TRUSTED_PROXIES>...
          [env: TRUSTED_PROXIES=]
      --crowdsec-timeout <CROWDSEC_TIMEOUT>
          [env: CROWDSEC_TIMEOUT=] [default: 10]
      --crowdsec-api <CROWDSEC_API>
          [env: CROWDSEC_API=] [default: http://localhost:8080]
      --crowdsec-apikey <CROWDSEC_APIKEY>
          [env: CROWDSEC_APIKEY=]
      --crowdsec-root-ca-cert <CROWDSEC_ROOT_CA_CERT>
          [env: CROWDSEC_ROOT_CA_CERT=] [default: /etc/crowdsec_bouncer/certs/ca.crt]
      --crowdsec-client-cert <CROWDSEC_CLIENT_CERT>
          [env: CROWDSEC_CLIENT_CERT=] [default: /etc/crowdsec_bouncer/certs/tls.crt]
      --crowdsec-client-key <CROWDSEC_CLIENT_KEY>
          [env: CROWDSEC_CLIENT_KEY=] [default: /etc/crowdsec_bouncer/certs/tls.key]
  -h, --help
          Print help
  -V, --version
          Print version
```
