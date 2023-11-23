# MicroProfile JWT Bridge

## Introduction

This specification enables mapping MicroProfile JWT tokens to Jakarta EE container APIs not included in the MicroProfile umbrella and provides a place where Jakarta EE specifications, such as Jakarta Security, can build requirements and seamless integrations with MicroProfile JWT.

In order not to introduce circular dependencies, this specification is to be created with the following scopes:

* Define the annotations to working with JWT authentication mechanisms such as how to configure the JWT claims. 

* Spec language would be added to state: Format of the JWT must comply with MP spec. Validation and handling of the JWT must comply with MP spec. 

* Move the optional section of MP JWT to the new bridge spec together with TCKs. 

* This specification is not limited to only Jakarta Security, and it may also include other relevant technologies.

## Proposal

* Define the Java language annotations to working with JWT authentication mechanisms such as how to configure the JWT claims.
`JwtAuthenticationMechanismDefinition` accepts a full set of properties mapped to MP JWT properties
E.g. `@JwtClaimsVerification` issuer maps `mp.jwt.verify.issuer`
* Spec language would be added to state:
Format of the JWT must comply with MP spec.
Validation and handling of the JWT must comply with MP spec.
Config must be accepted via annotation, however implementers may provide other methods of supplying config
Application code can access JWT claims by injecting the Jakarta SecurityContext
Implementation could utilize MP JWT under the covers, accept MP config, allow injection of MP JsonWebToken.
Usage is demonstrated below.

```
@JwtAuthenticationMechanismDefinition(
    jwtClaimsDefinition = @JwtClaimsDefinition(callerNameClaim = "upn", callerGroupsClaim = "groups"),
    publicKeyDefinition = @PublicKeyDefinition(key = "", location = "", algorithm = "RS256"),
    decryptionKeyDefinition = @PrivateKeyDefinition(location = "", algorithm = ""),
    jwtClaimsVerification = @JwtClaimsVerification(issuer = "", audiences = "", tokenAge = 0, tokenAgeExpression = "", clockSkew = 0, clockSkewExpression = ""),
    httpHeadersDefinition = @HttpHeadersDefinition(tokenHeader = "Authorization", cookieName = "Bearer"),
    jwksDefinition = @JwksDefinition(jwksConnectTimeout = 500, jwksConnectTimeoutExpression = "", jwksReadTimeout = 500, jwksReadTimeoutExpression = ""))
public class JwtSecuredServlet extends HttpServlet {

    @Inject jakarta.security.enterprise.SecurityContext securityContext;

    @Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // example of getting JWT claims from Jakarta SecurityContext
        jakarta.security.enterprise.identitystore.openid.JwtClaims jwtClaims = securityContext.getPrincipalsByType(...);
    }
}
```
* Move the optional section of MP JWT to the new bridge spec together with TCKs

## Documentation

For links to the latest maven artifacts, Javadoc and specification document, see the link:https://github.com/eclipse/microprofile-jwt-bridge/releases/latest[latest release].

## Project Links
* https://wiki.eclipse.org/MicroProfile/JWT_Bridge[Wiki Page]
* https://docs.google.com/document/d/13nIVDJ6uxen7d57rxyARX8-vqsf3HTvC6hHnhitGZ0w/edit[Hangout Meeting Notes]

### Continuous Integration
* https://ci.eclipse.org/microprofile/job/jwt-bridge-maven-snapshots/[Snapshot Build Jobs]
* https://ci.eclipse.org/microprofile/job/MicroProfile%20Releases/[Release Build Jobs]


