![DIF Logo](https://raw.githubusercontent.com/decentralized-identity/universal-resolver/master/docs/logo-dif.png)

# Universal Resolver Driver: did:iid

This is a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver/) driver for **did:iid** identifiers.

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)
* [DID Method Specification](https://github.com/InspurIndustrialInternet/iid/blob/main/doc/en/InspurChain_DID_protocol_Specification.md)


## Example DIDs

```
did:iid:3QUs61mk7a9CdCpckriQbA5emw8pubj6RMtHXP6gD66YbcungS6w2sa
did:iid:3k4KHKzF6FTiEpuBiCTMUYfzhDQyqZoye9196ECnYhcNvJyf4WjCQpP

```

## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t universalresolver/driver-did-iid
docker run -p 8080:8080 universalresolver/driver-did-iid

```

## Build (native Java)

	mvn clean install
	
## Driver Metadata

The driver returns the following metadata in addition to a DID document:
* `version`: The DID version.
* `proof`: Some proof info about the DID document.
* `created`: The DID create time.
* `updated`: The DID document last update time.


## Maintainer

- zoe Yian [@superzoeyian](https://github.com/superzoeyian)