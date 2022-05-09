# DAPS upgrade to v3

### Dear members and participants of the IDS Community,

#### TL;DR:

There is going to be a DAPS downtime tomorrow at 14:00 CET for a short period of time. We are
establishing a new, updated endpoint for an upcoming version 3.0 of the DAPS. /v2/token will be served
as ususal. A new /v3/token endpoint will be deployed to test compability and for step-by-step migration
to the new token format and .jwks-handling.

### Changes in detail:

we are currently launching an **updated version** of the Dynamic Attribute Provisioning Service (**DAPS**)
from the current version 2 to the new version 3. The changes are detailed in the next sections, and we
strongly encourage you to check whether your implementation of a connector is fully compatible with
the new version. We incorporated these changes to keep up with existing standards (including IDS-G)
and best practices.

We try to keep the burden of upgrading old clients to a minimum. **The old version 2 will be maintained
further** for some time. So, the https://daps.aisec.fraunhofer.de/v2/token endpoint will continue to work and will be
served by a legacy script that converts between the old and the new version.
Keep in mind however that the issued tokens may not be accepted by every component in the data space for future
deployments.

### What is changing?

Changes to the DAT are twofold. The first major change involves the DAT's JOSE-Header. Here is an
example:

```json
{
  "kid": "default",
  "typ": "at+jwt",
  "alg": "RS256"
}
```

We noticed that some connectors (notably DSC, Version < 7.0.0) are relying on the "kid" having a pre-
defined never-changing value (e.g., "default"), which had to be configured manually. To support key
rollover, we are now assigning unique "kid"s to the keys. The correct DAT signature verification
procedure is thus:

1. Upon retrieval of a DAT, decode the header to retrieve the kid.
2. Retrieve the corresponding verification key from the DAPS JWKS. The JWKS's location
   can be determined in the following two ways:
    1. If the DAPS supports RFC 8414 (the Fraunhofer DAPS and any local setups
       following https://github.com/International-Data-Spaces-Association/omejdn-daps
       do this), you may retrieve the JWKS location (as well as the expected Issuer
       identifier and the token endpoint URL) from the corresponding Server Metadata
       Document. For the Testing instance V3 (see below), this document is located at
       https://daps-dev.aisec.fraunhofer.de/.well-known/oauth-authorization-server/v3, and the JWKS can be retrieved
       from the URL listed under jwks_url. Going forward,
       this is the recommended solution.
    2. Alternatively, the JWKS may be manually specified as part of the component's
       configuration according to the DAPS service documentation. Note that it is NOT
       interoperable to simply assume the JWKS to be located at /.well-known/jwks.json
       for every DAPS instance. The current location for the Fraunhofer DAPS is
       https://daps.aisec.fraunhofer.de/.well-known/jwks.json.
3. Use the key with the correct kid to verify the DAT. If the JWKS does not include such a
   key, or the verification fails, the DAT is invalid.

The second major change concerns the DAT's contents, aligning them with existing specifications
(including IDS-G). Here is an example of a DAT as it has been issued for V2:

```json
{
  "scopes": [
    "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL"
  ],
  "aud": "idsc:IDS_CONNECTORS_ALL",
  "iss": "https://daps.aisec.fraunhofer.de",
  "nbf": 1637156074,
  "iat": 1637156074,
  "jti": "MjU0NDg0NzkzNzMwOTQzMjU2NQ==",
  "exp": 1637159674,
  "securityProfile": "idsc:BASE_SECURITY_PROFILE",
  "referringConnector": "http://testidsa9.demo",
  "@type": "ids:DatPayload",
  "@context": "https://w3id.org/idsa/contexts/context.jsonld",
  "transportCertsSha256": "c68d9e6ba3f1799bcbe5bec9d7d98b15b0ef2f292c80f6bca994178aa95ae10d",
  "sub": "63:44:DA:B1:EA[...]:50:2F:E6:65:43:5D:E8"
}
```

The corresponding new version is shown below:

```json
{
  "scope": "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL",
  "aud": [
    "idsc:IDS_CONNECTORS_ALL"
  ],
  "iss": "http://localhost:4567",
  "nbf": 1637156037,
  "iat": 1637156037,
  "jti": "MzAwNzc4NjQ4MDM5MzA5OTU2Ng==",
  "exp": 1637159637,
  "client_id": "63:44:DA:B1:EA[...]:50:2F:E6:65:43:5D:E8",
  "securityProfile": "idsc:BASE_SECURITY_PROFILE",
  "referringConnector": "http://testidsa9.demo",
  "@type": "ids:DatPayload",
  "@context": "https://w3id.org/idsa/contexts/context.jsonld",
  "transportCertsSha256": "c68d9e6ba3f1799bcbe5bec9d7d98b15b0ef2f292c80f6bca994178aa95ae10d",
  "sub": "63:44:DA:B1:EA[...]:50:2F:E6:65:43:5D:E8"
}
```

All changes are in accordance with https://www.rfc-editor.org/rfc/rfc9068.html#name-data-structure.
The DAT content changes in detail:

- "scopes" has been changed to "scope" in accordance
  with https://www.rfc-editor.org/rfc/rfc9068.html#name-authorization-claims.
- "aud" is (in general) an array, but may be a string if it only contains one value.
  Implementers are advised to either use an off-the-shelf JWT parsing library.
- "client_id" was added. With the used client_credentials grant, it is equal to the "sub"
  claim.

From our testing these changes seem to not pose a problem for the tested connectors, but for some
distinct IDS components, including some Clearing House implementations.

### Where can I test if my connector will work with V3?

An instance for testing the V3 endpoints is available at DAPS-Dev. Please
visit https://daps-dev.aisec.fraunhofer.de/.well-known/oauth-authorization-server/v3 for up-to-date Server Metadata. It
currently lists the following relevant endpoints:

- Issuer: https://daps-dev.aisec.fraunhofer.de
- Token Endpoint: https://daps-dev.aisec.fraunhofer.de/v3/token
- JWKS URI: https://daps-dev.aisec.fraunhofer.de/.well-known/jwks.json

Once the upgrade is performed, the actual DAPS will use the same URLs, with daps-dev being replaced
by daps.

Please let us know if you have any difficulties using the new version 3 DAPS-upgrade!

### What to do next?

If you use the DataSpace Connector version 7.0.0 or above, you should be fine. Likewise, if you use the
Fraunhofer AISEC Trusted Connector version 6.0.0 or above, you should be fine.

If you use one of those connectors at a lower version, you should upgrade to the current
versions. /v2/token will be served

If you use another connector, which relies on the IDS-Messaging-Services, make sure it uses at least
version 6.0.0.

If you use another connector, make sure to test your instance against the DAPS-Dev (see above). You
might have to implement the above changes. If you need guidance for the relevant standards, please
contact us.

The same applies if you run other IDS components. Note that you need to support V3 components
unless you know for certain that every communication partner will be using V2 components only. Going
forward, V2 support is optional.

### Future changes to be aware of?

We are currently considering changing the Issuer identifier ("iss" in the DAT) to include a path aka. the
version number (I.e. "iss" would be "https://daps.aisec.fraunhofer.de/v3"). This is also in accordance
with the relevant standards and may help diagnosing upgrade issues in the future. It will also however
require support for the validation of tokens from multiple DAPS instances in the transition phases. This
is a future change, and we will notify all participants beforehand. Implementors of new IDS components
are advised to

- Make configurable a list of trustworthy issuer identifiers, and
- Upon receipt of a DAT, retrieve the corresponding DAPS�s verification keys via the Server
  Metadata as described in RFC 8414. Please contact us if you have any questions.

### Contact

If you have any questions, please file an issue at https://github.com/International-Data-Spaces-Association/omejdn-daps.
Issues related to components not being compatible with these changes
should be raised at those components.

#### Best

Your DAPS team.
