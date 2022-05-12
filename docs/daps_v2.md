# Dynamic Attribute Provisioning Service (DAPS)

The infrastructure component "Dynamic Attribute Provisioning Service" (DAPS)
in a given IDS ecosystem enables enrichment of identities of organisations
and connectors with additional attributes.

DAPS can be understood (like the [Certificate Authority](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Components/IdentityProvider/CA/README.md), too) as building block of the construct of an
[IDS Identity Provider](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Glossary/README.md#identity-provider).

These attributes are embedded by the DAPS into a [Dynamic Attribute Token (DAT)](#dynamic-attribute-token-dat).
The advantages of this technique of *dynamic attribute provisioning* instead
of embedding them into [X.509 certificates](https://en.wikipedia.org/wiki/X.509)
are:

- Attribute revocation does not enforce certificate revocation and re-issuance.
  This is also true if new attributes are added.
- By defining scopes or attribute sets, only the needed attributes can be
  included in the DAT. This limits information leakage, so only needed
  attributes are communicated.
- Baseline certificates can be issued to enable connector deployment
  in uncomplicated manner.
- More complex scenarios can be created as soon as attributes are
  assigned later on.

See also:
- [Glossary "Dynamic Attribute Provisioning Service"](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Glossary/README.md#dynamic-attribute-provisioning-service)
- Shortcut: `DAPS`

---

## Unique Identifier

Each Connector in the IDS needs a valid, outlasting and unique
identifier, never be re-used for any other resource inside the IDS ecosystem.

The architecture aims to be open to multiple [Certificate Authorities](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Components/IdentityProvider/CA/README.md)
(CAs) issuing certificates. This means, a truly unique identifier needs to consist of
the issuer of the certificate and the subject identifier. For an easy machine readable
identifier, two ´X.509v3´ extensions will be used:

- Subject Key Identifier (SKI)
- Authority Key Identifier (AKI)

The concatenation of ´SKI´ and ´AKI´ provides a unique identifier valid - even if multiple
CAs are able to issue valid certificates.

EXAMPLE (snippet from a X.509 certificate):

```text
...
X509v3 extensions:
    X509v3 Subject Key Identifier:
        DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A
    X509v3 Authority Key Identifier:
        keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8
...
```

... leads to a [connectors](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Components/Connector/README.md) `unique identifier`:

```text
DD:CB:FD:0B:93:84:33:01:11:EB:5D:94:94:88:BE:78:7D:57:FC:4A:keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8
```

In examples and for reasons of readability editors might use

```text
SKI:AKI
```

See also:
- [Glossary "Dynamic Attribute Token"](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Glossary/README.md#dynamic-attribute-token)
- Shortcut: `DAT`
- [X.509 certificates](https://en.wikipedia.org/wiki/X.509)

---


## Request token that is handed in at DAPS side

| **Field name**  | **mandantory**  | **cardinality**  | **content**                                                                                                                                                                                                                                                                             |
|:----------------|:----------------|:-----------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`@context`**  | yes             | 1                | The JSON-LD context containing the IDS classes, properties and instances. Must be "https://w3id.org/idsa/contexts/context.jsonld".                                                                                                                                                      |
| **`@type`**     | yes             | 1                | In the context of the IDS, the request payload is an RDF instance and therefore must state that it has "@type" : "ids:DatRequestToken".                                                                                                                                                 |
| **`sub`**       | yes             | 1                | Subject the requesting connector the token is created for. This is the connector requesting the DAT. The "sub" value must be the  combined entry of the SKI and AKI of the IDS X509 as presented in Sec. 4.2.1.  In this context, this is identical to "iss".                           |
| **`exp`**       | yes             | 1                | Expiration date of the token. Can be chosen freely but should be limited to a short period of time (e.g., one minute).                                                                                                                                                                  |
| **`iat`**       | yes             | 1                | Timestamp the token has been issued.                                                                                                                                                                                                                                                    |
| **`nbf`**       | yes             | 1                | "Valid not before": For practical reasons this should be identical to iat. If the system time is not in synch with the DAPS, the request token will be rejected (e.g., nbf is in the future).                                                                                           |
| **`aud`**       | yes             | 1                | The audience of the token. This can limit the validity for certain connectors. This is a feature designed for future use. Currently, only "idsc:IDS_CONNECTORS_ALL" will be accepted by the DAPS.                                                                                       |
| **`iss`**       | yes             | 1                | According to RFC 7519 Sec. 4.1.1, the issuer is the component which created and signed the JWT. In the context of the IDS, this must be a valid connector. The "iss" value must be the combined entry of the SKI and AKI of the Connectors X509 certificate as presented in Sec. 4.2.1. |

## Request call to get a token

`client_assertion` id the base64 encoded request token, shown under
["Request token that is handed in at DAPS side"](#request-token-that-is-handed-in-at-daps-side).

| **FormBody Attribute**      | **content**                                                                                                                                                                                                          |
|:----------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`grant_type`**            | OAuth based grant type: `client_credentials`.                                                                                                                                                                        |
| **`client_assertion_type`** | See [JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://tools.ietf.org/html/rfc7523).                                                                                |
| **`client_assertion`**      | The signed and base64 encoded request token. Paste the example to jwt.io to see the decoded JWT. The token is signed with the connectors private key belonging to the public key contained in the X.509 certificate. |

### Example of a "request call to get a token"

```http request
POST /token
Host: https://daps.aisec.fraunhofer.de
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJBNTowQzpBNTpGMDo4NDpEOTo5MDpCQjpCQzpEOTo1NzozQTowNDpDODo3Rjo5MzpFRDo5NzpBMjo1MjprZXlpZDpDQjo4QzpDNzpCNjo4NTo3OTpBODoyMzpBNjpDQjoxNTpBQjoxNzo1MDoyRjpFNjo2NTo0Mzo1RDpFOCIsImV4cCI6MTYzMjk4OTU2OSwiaWF0IjoxNjMyOTgyMzY5LCJpc3MiOiJBNTowQzpBNTpGMDo4NDpEOTo5MDpCQjpCQzpEOTo1NzozQTowNDpDODo3Rjo5MzpFRDo5NzpBMjo1MjprZXlpZDpDQjo4QzpDNzpCNjo4NTo3OTpBODoyMzpBNjpDQjoxNTpBQjoxNzo1MDoyRjpFNjo2NTo0Mzo1RDpFOCIsIm5iZiI6MTYzMjk4MjM2OSwiQGNvbnRleHQiOiJodHRwczovL3czaWQub3JnL2lkc2EvY29udGV4dHMvY29udGV4dC5qc29ubGQiLCJhdWQiOiJpZHNjOklEU19DT05ORUNUT1JTX0FMTCIsIkB0eXBlIjoiaWRzOkRhdFJlcXVlc3RUb2tlbiJ9.Um8G7C2GqEYIfCq_24uPXV1HRufPwAZGqYYShpkaUyB8FNWxBN05TNEkJa-JLEmBwJ3O0c6eSM3LyMnoZmPlMsONdHh3No6LRWLsHenHADhgUnoUO_L3ar-XYAKyPxssyrVVzv4u_pg5WT5AtWuTXxhS-X9dV7Lr3IpDyRg7kJViuv31iCeaXNG8YspCiXmRVHr6tboom-PUj0ZS6BB2MHn3TUkGa8v1QdXlRMHHPJOo5W5s2BDWgJyBCwy2v_dvpJzZATHknsvysU4r2qnzvS5E_7MsWj8bzxxTRdJqltq9vXW358n0_m6H9JT37xFwzQX7Kjyqfw9wnwzOqeLXBw
&scope=idsc:IDS_CONNECTOR_ATTRIBUTES_ALL

```

> **!!!** REMARK: NO line breaks in front of '&', done for better readability only **!!!**

See also:
- [JSON-LD](https://en.wikipedia.org/wiki/JSON-LD)
- [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier)

---

## Dynamic Attribute Token Content

The DAPS issues the requested DAT, if authentication succeeds.

The DAT has these header fields:

| **Field name**  | **mandantory**  | **cardinality**  | **content**                                                                                            |
|:----------------|:----------------|:-----------------|:-------------------------------------------------------------------------------------------------------|
| **`typ`**       | yes             | 1                | The token type. Must be "JWT".                                                                         |
| **`kid`**       | yes             | 1                | Key id used to sign that token. Must match the jwks.json entry found at daps-url/.well-known/jwks.json |
| **`alg`**       | yes             | 1                | Algorithm used to sign the token.                                                                      |

The DAT has these payload fields:

| **Field name**             | **mandantory**  | **cardinality**  | **content**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:---------------------------|:----------------|:-----------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`@context`**             | yes             | 1                | The JSON-LD context containing the IDS classes, properties and instances. Must be "https://w3id.org/idsa/contexts/context.jsonld".                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **`@type`**                | yes             | 1                | In the context of the IDS, the request payload is an RDF instance and therefore must state that it has "@type" : "ids:DatRequestPayload".                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **`@type`**                | yes             | 1                | In the context of the IDS, the DAT payload is an RDF instance and therefore must state that it has "@type" : "ids:DatPayload".                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **`iss`**                  | yes             | 1                | According to RFC 7519 Sec. 4.1.1, the issuer is the component which created and signed the JWT. In the context of the IDS, this must be a valid DAPS. The "iss" value must be a valid URL for the DAPS such as "https://daps.aisec.fraunhofer.de".                                                                                                                                                                                                                                                                                                                            |
| **`sub`**                  | yes             |                  | Subject the requesting connector the token is created for. This is the connector requesting the [DAT](#dynamic-attribute-token-dat). The `sub` value must be the  combined entry of the `SKI` and `AKI` of the IDS X509 as presented in Sec. 4.2.1.                                                                                                                                                                                                                                                                                                                           |
| **`exp`**                  | yes             | 1                | Expiration date of the token. Can be chosen freely but should be limited to a short period of time (e.g., one minute).                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **`jti`**                  | yes             | 1                | Unique identifier of the jwt.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **`iat`**                  | yes             | 1                | Timestamp the token has been issued.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **`nbf`**                  | yes             | 1                | "Valid not before" (`nbf`): for practical reasons this should be identical to `iat`. If systems time is not aynchronized with the DAPS, the request token will be rejected (so, `nbf` is in the future).                                                                                                                                                                                                                                                                                                                                                                      |
| **`aud`**                  | yes             | 1                | The audience of the token. This can limit the validity for certain connectors.  Currently, only "idsc:IDS_CONNECTORS_ALL" is supported.                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **`scopes`**               | yes             | 1..*             | List of scopes. Currently, the scope is limited to "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL" but can be used for claim scoping purposes in the future.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **`securityProfile`**      | yes             | 1                | States that the requesting connector conforms to a certain security profile and has been certified to do so. The value must be an instance of the ids:SecurityProfile class, e.g. "idsc:TRUST_SECURITY_PROFILE".                                                                                                                                                                                                                                                                                                                                                              |
| **`referringConnector`**   | `opt`           | 0..1             | The URI of the subject, the connector represented by the DAT. Is used to connect identifier of the connector with the self-description identifier as defined by the IDS Information Model. A receiving connector can use this information to request more information at a Broker or directly by dereferencing this URI.                                                                                                                                                                                                                                                      |
| **`transportCertsSha256`** | `opt`           | 0..*             | Contains the public keys of the used transport certificates. The identifying X509 certificate should not be used for the communication encryption. Therefore, the receiving party needs to connect the identity of a connector by relating its hostname (from the communication encryption layer) and the used private/public key pair, with its IDS identity claim of the DAT. The public transportation key must be one of the "transportCertsSha256" values. Otherwise, the receiving connector must expect that the requesting connector is using a false identity claim. |
| **`extendedGuarantee`**    | `opt`           | 0..*             | In case a connector fulfills a certain security profile but deviates for a subset of attributes, it can inform the receiving connector about its actual security features. This can only happen if a connector reaches a higher level for a certain security attribute than the actual reached certification asks for. A deviation to lower levels is not possible, as this would directly invalidate the complete certification level.                                                                                                                                       |


## Dynamic Attribute Token (DAT)

An example of a complete DAT, including header and payload is shown below:

```json lines
{
  "typ": "JWT",
  "kid": "default",
  "alg": "RS256"
}
.
{
  "scopes": [
    "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL"
  ],
  "aud": "idsc:IDS_CONNECTORS_ALL",
  "iss": "https://daps.aisec.fraunhofer.de",
  "nbf": 1632982369,
  "iat": 1632982369,
  "jti": "OTAyNTE1OTMzNTczMDgyMzUxNg==",
  "exp": 1632985969,
  "securityProfile": "idsc:TRUST_SECURITY_PROFILE",
  "referringConnector": "http://consumer-core.demo",
  "@type": "ids:DatPayload",
  "@context": "https://w3id.org/idsa/contexts/context.jsonld",
  "transportCertsSha256": "c15e6558088dbfef215a43d2507bbd124f44fb8facd561c14561a2c1a669d0e0",
  "sub": "A5:0C:A5:F0:84:D9:90:BB:BC:D9:57:3A:04:C8:7F:93:ED:97:A2:52:keyid:CB:8C:C7:B6:85:79:A8:23:A6:CB:15:AB:17:50:2F:E6:65:43:5D:E8"
}
.
<signature>
```

See also:
- [Info Model : idsc:USAGE_CONTROL_POLICY_ENFORCEMENT](https://github.com/International-Data-Spaces-Association/InformationModel/blob/develop/codes/SecurityGuarantee.ttl)
- [Glossary "Dynamic Attribute Token"](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Glossary/README.md#dynamic-attribute-token)
- Shortcut: `DAT`

---

## Requests

Collection of valid request templates can be found [here](https://github.com/International-Data-Spaces-Association/IDS-G-pre/tree/main/Components/IdentityProvider/DAPS/requests/README.md).

## REST API description

REST API description can be found
[here](https://app.swaggerhub.com/apis/IDS_Association/DynamicAttributeProvisioningService).

---
