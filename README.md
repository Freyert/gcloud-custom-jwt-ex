# gcloud-custom-jwt-ex
An example instructing how to sign and validate custom JWTs against GCloud.



# How to Use
1. Provision a Service Account Key
2. Move the JSON into this directory and name it `service-account.json`.
3. `go run .`

# How does it work?

When you provision a service account key, not only do you receive the private key,
but the public certificate is hosted for you on a public endpoint.

Given the private key we can sign JWTs, and clients can validate signatures with the
public certificates.

Caveats:

1. It is not in JWKS format so it still needs more work to act as a rudimentary
OIDC provider for Envoy.
2. It's probably better to use the KMS service to create and manage signing
keys.
3. Could also use KMS to sign payloads without distributing the key, but that
might get expensive.
