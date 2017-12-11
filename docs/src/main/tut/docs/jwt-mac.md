---
layout: docs
number: 5
title: "JWT"
---
# JWT 

Our JWT implementation addresses [this](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) vulnerability
through the scala type system. As all `JWTs` are typed, both during encoding and decoding, there is no way to parse an arbitray JWT for
an endpoint before knowing the expected algorithm, thus, we avoid the ol' switcheroo.

The general imports for this module are as follows:
```tut:silent
import tsec.jwt._
import tsec.jws.mac._
import tsec.mac.imports._
import scala.concurrent.duration._
```

To create custom claims, use the JWTClaims object:

```tut
  val claims = JWTClaims.build(expiration = Some(10.minutes))
```

The JWT module comes with two ways to work with JWT by default: by using `Either` to handle errors,
 or into a Target `F[_]` with a `MonadError[F, Throwable]`.
 
```tut:silent
  import cats.syntax.all._
  import cats.effect.Sync

  /** You can interpret into any target Monad with an instance of Sync[F] using JwtMac */
  def jwtMonadic[F[_]: Sync]: F[JWTMac[HMACSHA256]] =
    for {
      key <- HMACSHA256.generateLift[F]
      jwt <- JWTMac.build[F, HMACSHA256](claims, key) //You can sign and build a jwt object directly
      verifiedFromObj <- JWTMac
        .verifyFromInstance[F, HMACSHA256](jwt, key) //You can verify the jwt straight from an object
      stringjwt  <- JWTMac.buildToString[F, HMACSHA256](claims, key)       //Or build it straight to string
      isverified <- JWTMac.verifyFromString[F, HMACSHA256](stringjwt, key) //You can verify straight from a string
      parsed     <- JWTMac.verifyAndParse[F, HMACSHA256](stringjwt, key)   //Or verify and return the actual instance
    } yield parsed

  /** Or using an impure either interpreter */
  val jwt: Either[Throwable, JWTMac[HMACSHA256]] = for {
    key             <- HMACSHA256.generateKey()
    jwt             <- JWTMacImpure.build[HMACSHA256](claims, key) //You can sign and build a jwt object directly
    verifiedFromObj <- JWTMacImpure.verifyFromInstance[HMACSHA256](jwt, key)
    stringjwt       <- JWTMacImpure.buildToString[HMACSHA256](claims, key) //Or build it straight to string
    isverified      <- JWTMacImpure.verifyFromString[HMACSHA256](stringjwt, key) //You can verify straight from a string
    parsed          <- JWTMacImpure.verifyAndParse[HMACSHA256](stringjwt, key) //Or verify and return the actual instance
  } yield parsed
```