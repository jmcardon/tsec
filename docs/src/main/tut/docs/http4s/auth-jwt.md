---
layout: docs
number: 9
title: "JWT Authentication"
---

# JWT Authenticator

This authenticator uses [JWT](https://jwt.io) for authentication. The contents of the actual identity 
are transported in the `subject` claim, and are encrypted if you choose the `statelessEncrypted` or
`statelessEncryptedArbitrary` option. 


### Defaults
The authenticator `stateless` and `withBackingStore` methods default
to transporting it in the `Authorization` header as a Bearer token. If you must transport it in an arbitrary header,
use the methods that end in `Arbitrary`, i.e `statelessArbitrary`.

For the cases of a custom header, JWT authenticator uses `TSecJWTSettings` for configuration:

```scala
  final case class TSecJWTSettings(
      headerName: String = "X-TSec-JWT",
      expirationTime: FiniteDuration,
      maxIdle: Option[FiniteDuration]
  )
```

And for storage, a `AugmentedJWT[A, Id]`, where `Id` is your Id type (i.e UUID, Int, etc).

Notes:
* Choose between one of HMACSHA256, HMACSHA384 or HMACSHA512. **Recommended default: HMACSHA256**.
* Not vulnerable to [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery).
* Okay to use with `CORS`
* Tsec jwts are typed, so not vulnerable to [this](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
* Stateless or stateful.

### Authenticator Creation

```tut:silent
import cats.effect.IO

import cats.Id
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.common.SecureRandomId
import tsec.mac.imports.{HMACSHA256, MacSigningKey}
import scala.concurrent.duration._

object jwtStatefulExample {

  import http4sExamples.ExampleAuthHelpers._

  val jwtStore =
    dummyBackingStore[IO, SecureRandomId, AugmentedJWT[HMACSHA256, Int]](s => SecureRandomId.coerce(s.id))

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  //Our signing key. Instantiate in a safe way using .generateKey[F]
  val signingKey: MacSigningKey[HMACSHA256] = HMACSHA256.generateKey[Id] 

  val jwtStatefulAuth =
    JWTAuthenticator.withBackingStore(
    expiryDuration = 10.minutes, //Absolute expiration time
    maxIdle        = None,
    tokenStore     = jwtStore,
    identityStore  = userStore,
    signingKey     = signingKey
    )

  val Auth =
    SecuredRequestHandler(jwtStatefulAuth)

  /*
  Now from here, if want want to create services, we simply use the following
  (Note: Since the type of the service is HttpService[IO], we can mount it like any other endpoint!):
   */
  val service: HttpService[IO] = Auth {
    //Where user is the case class User above
    case request@GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, User, AugmentedJWT[HMACSHA256, Int]] = request
      Ok()
  }

}
```
