title: Support for external PKI for authentication of edge nodes

# Motivation

**TBD. synchronize with https://github.com/kubeedge/kubeedge/issues/3100**

# Driving Forces

The following chapters list the driving forces that guide the proposed changes.

## Secure authentication

The main goal is the secure authentication of the edge nodes: Before a successful communication with the cloudhub is allowed, the _identity_ of the edge node has to be established. The authentication has to be performed without user interaction, as edge nodes are commonly expected to work autonomously without user input.
Currently, two forms of authentication are used:

* Client certificate: A predefined X.509 client certificate is passed in the configuration to the edgenode. This certificate is used to authenticate the edgenode to the cloud hub, the communication may only proceed, if the certificate is valid and signed by a certification authority known to the cloudhub. The main disadvantage of this approach is, that currently no automatic mechanisms for revoking or replacing this certificate are available.

* Bearer token that is provided manual via configuration: The edgenode presents a pre-configured JWT bearer token to authenticate itself. Using this token the cloudhub _generates_ a new client certificate that is provided to the edgenode. Further authentication is done using this certificate. The obvious issues with this approach are
    * The JWT token must be configured manually
    * No token refresh mechanism is defined
    * The cloudhub must perform tasks of a certification authority with obvious security impacts

## Moving security functionality to external facilities

Currently, considerable amounts of code within KubeEdge perform authentication and authorization functionality, e.g. the cloudhub may function as a _certification authority_ to create new (client-) X.509 certificates. This requires the storing and handling of sensitive data, e.g. private cryptographic keys. Furthermore, traditionally the correct implementation of security functionality is non-trivial. Therefore it is advisable, to move as much security relevant functionality to systems that are explicitly implemented for this kind of operations. Removing, resp. _deprecating_, security relevant implementations and sensitive data considerably reduces the attack surfaces of the overall system.

## Autonomous Renew

To adequate security it is important, that credentials for authentication are not hardcoded for long term usage, but periodically refreshed. For IoT devices it is especially important, that this is done _autonomously_, i.e. executed without further user interaction. This requires, that

* X.509 client certificates and JWT tokens have a restricted lifetime to ensure regular renewal
* An automatic process exists, that allows to easily renew these credentials.

A challenge for this is, that the identity of the requesting edgenode has to be established, before a fresh client certificate may be provided. Therefore, a _bootstrapping_ process is required.
 
## Revocation and Blocking of Unauthorized Access

Mobile IoT devices are at risk of getting lost or stolen. In this case it is desirable, to lock the access to the cloudhub of this device as soon as possible. The main building blocks for this are

* Using only _short-lived_ credentials for the device, so that a refresh is required periodically
* Block the facility for refreshing the credentials as soon as possible to minimize the attack surface for possible rogue devices.

Additionally it is advisable to only _lock_ the access for the "lost" device, as a recovered device may be unlocked and reused again.
This 

## Backwards Compatibility

Currently, the KubeEdge frameworks provides a considerable amount of functionalities to ensure authentication and authorization. Consequently, a lot of configuration and implementation already exist that rely on this functionality. Therefore it is essential, that the current functionally _remains backward compatibility_ to protect existing investments in setup and operation of KubeEdge. This requires, that all new functionality is _added side-by-side_ with the existing functions. So,

* If needed, new configuration settings must be added without changing the syntax or semantics of already existing settings.
* Suitable default values must be provided for new functionalities that ensure, that the new functionality does not interfere with existing configurations. Optimally, all new functionality should be _disabled_ by default.

## Tamper proof

As the identity of the edgenode is the root of all security aspects for the system, it is essential, that the identity information of the device is stored as secure as possibly.

# Architecture of the Proposed Change

## Motivation

As discussed above, it would be advisable to move security relevant functions and data to a dedicated system, that is designed for such tasks and explicitly hardened. One example of such a system would be [Hashicorp Vault](https://www.vaultproject.io/docs). This system may be used as _security module_ that

* securely stores sensitive data, e.g. private keys 
* may be used as a _certification authority_ with all associated functionality:
    * Issuing of new certificates
    * Revocation of certificates
    * Facilities to implement certificate renewals
* Authentication mechanisms
* Secret management

Additionally vault is a cloud friendly application that may be operated highly available within a kubernetes cluster. 

## High Level Overview

The following diagram shows the high level overview of the system:

 ![](http://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/edgefarm/kubeedge/vault/docs/images/proposals/pki-system-components.puml)

 Within the cloud environment an instance of vault is made available. 
 
Vault will perform the following tasks:

* For the edge hub:
    * Authenticate the cloud hub pods for certificate handling
    * Provide X.509 server certificates for the edge node interfaces
    * Provide periodic X.509 certificate renewal for the server certificates
    * Revoke edge hub client certificates
    * Provide revocation lists for edge hub client certificates
* For the cloud hub:
    * Authenticate the edge hub nodes for certificate handling and to establish the identity of the cloud hub node 
    * Allow creation of X.509 client certificates to secure the communication with the cloud hub. The certificates must be signed with a ca certificate that allows the cloud hub to validate the client certificate
    * Allow renewal of the client certificate
 
The security system of Vault allows it, to define in fine granularity, which client may invoke which operation. For example, it can be defined that a client may retrieve a newly generated client certificate, however, the X.500 common name and additional attributes of the certificate are predefined.

# Use Cases
## Cloud Hub

These are detailed use cases for the cloud hub

### Authenticate to Vault

As a first step, the cloud hub pods have to authenticate to Vault in order to gain the privileges for all following use cases. As the cloud hub is running within kubernetes, the methods [provided by Vault](https://www.vaultproject.io/docs/platform/k8s) may be used. Basically, these are

* Secret injection via the Vault agent injector
* Secret injection via the container storage injection (CSI) facility of kubernetes

[Recommended](https://www.hashicorp.com/blog/kubernetes-vault-integration-via-sidecar-agent-injector-vs-csi-provider) is to use the Vault agent injector for now, as this is the more flexible of both solutions, and supports caching and secret rotation


### Generate a Server Certificate

After authentication the server may create an X.509 certificate for itself that is used in the communication with the edge nodes. For this

* Vault must be configured to work as a [certification authority](https://learn.hashicorp.com/tutorials/vault/pki-engine?in=vault/secrets-management)
* A suitable Vault role must be defined, that defines the parameters of the certificate to be generated (validity period, X.500 common name etc.)

> Note:
> The Vault documentation recommends to use a _separate_ root certification authority. However, it is technically feasible to operate the root ca within the same Vault instance.

### Validate a Client Certificate

When a client connects to the cloud hub http server, the provided client certificate must be validated:

* Validity period is not stale
* Serial number of the offered client certificate has not been revoked
* The passed certificate is signed by a valid certificate chain

 ![](http://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/edgefarm/kubeedge/vault/docs/images/proposals/pki-cloudhub-clientvalidation.puml)

The validation of the client interface must be done programmatically on establishing the connection and is done by the client libraries. Vault does not provide functionality for _validating a certificate chain_.

## Automatic Renewal

The server certificate should be periodically renewed. An automatic job may retrieve a new certificate and replace the one currently used. As the certificate is signed by a valid certification authority, the certificate change will be transparent for the connecting edge nodes.


## Edge Hub

These are detailed use cases for the edge hub

### Authenticate to Vault

The initial step for the edge hub nodes is to establish their identity with Vault. For this, every edge node must be configured with a _bootstrap certificate_. This certificate

* is only used for authentication to Vault, not for communicating with the cloud hub. This might be enforced by signing these certificates with another CA certificate than the CA certificate used for communication.
* Is long lived to avoid the requirement for frequent renewal. However, the bootstrap certificate _should_ be renewed periodically. These periods should be aligned with the physical maintenance intervals of the edge devices.
* Must be protected tamper proof within the device.

The authentication is straight forward:
 ![](http://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/edgefarm/kubeedge/vault/docs/images/proposals/pki-edgehub-auth.puml)

### Renew the token

The token has a limited validity and must be renewed with the appropriate [Vault API](https://www.vaultproject.io/api-docs/auth/token#renew-a-token-self).

### Generate a Client Certificate

Using the bearer token the edge hub may request a new certificate. This requires, that 

* A appropriate _Vault role_ has been defined, that defines the parameters of the new X.509 certificate, e.g. common name and validity period
* A _Vault policy_ has been defined, that only allows requesting a certificate for the correct name of the requesting edge node

It is recommended to keep the validity period of the generated certificate as short as possible, e.g. a single day.

### Renew a Client Certificate

As the client certificate is short lived, it requires periodic renewal. This is identical the generation of a new certificate.

## Device enrollment

With the use cases described above the enrollment of a new device is automatic, as the device will request a new certificate without further user interaction. The mandatory precondition is, that the initial _bootstrap certificate_ has been provided via configuration.
