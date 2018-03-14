---
layout: docs
number: 5
title: "JWT"
---
# JWT 

Our JWT implementation addresses [this](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) vulnerability
through the scala type system. As all `JWTs` are typed, both during encoding and decoding, there is no way to parse an arbitrary JWT for
an endpoint before knowing the expected algorithm, thus, we avoid the ol' switcheroo.

The general imports for this module are as follows:
```tut:silent
import cats.syntax.all._
import cats.effect.Sync
import tsec.jwt._
import tsec.jws.mac._
import tsec.mac.jca._
import scala.concurrent.duration._
```

To create JWT Claims, use the JWTClaims object:

```tut
  def claimsWithDuration[F[_]: Sync]: F[JWTClaims] = JWTClaims.withDuration[F](expiration = Some(10.minutes))
```

We can also add custom claims to a JWT object. Imagine we have some custom case class (though it can be any type):
```tut:silent
  import io.circe._
  import io.circe.syntax._
  import io.circe.generic.semiauto._

  case class Doge(suchChars: String, much32Bits: Int, so64Bits: Long)
  
  //Note: Normally this would be in the companion
  implicit val encoder: ObjectEncoder[Doge] = deriveEncoder[Doge]
  implicit val decoder: Decoder[Doge]       = deriveDecoder[Doge]
  val WowSuchClaim                          = "Doge"
```

We can add it via explicit json serialization as such:

```tut
  JWTClaims(customFields = Seq(WowSuchClaim -> Doge("w00f", 8008135, 80085L).asJson))
```


The JWT module comes with two ways to work with JWT by default interpreting
 into a Target `F[_]` with a `Sync[F]`, or interpreting into `Either[Throwable, A]`
 if you do not like writing pure code.
 
```tut:silent
  /** You can interpret into any target Monad with an instance of Sync[F] using JwtMac */
  def jwtMonadic[F[_]: Sync]: F[JWTMac[HMACSHA256]] =
    for {
      key             <- HMACSHA256.generateKey[F]
      claims          <- JWTClaims.withDuration[F](expiration = Some(10.minutes))
      jwt             <- JWTMac.build[F, HMACSHA256](claims, key) //You can sign and build a jwt object directly
      verifiedFromObj <- JWTMac.verifyFromInstance[F, HMACSHA256](jwt, key) //Verify from an object directly
      stringjwt       <- JWTMac.buildToString[F, HMACSHA256](claims, key) //Or build it straight to string
      isverified      <- JWTMac.verifyFromString[F, HMACSHA256](stringjwt, key) //You can verify straight from a string
      parsed          <- JWTMac.verifyAndParse[F, HMACSHA256](stringjwt, key) //Or verify and return the actual instance
    } yield parsed
    
  import java.time.Instant

  /** Or using an impure either interpreter */
  val impureClaims = JWTClaims(expiration = Some(Instant.now.plusSeconds(10.minutes.toSeconds)))

  val jwt: Either[Throwable, JWTMac[HMACSHA256]] = for {
    key             <- HMACSHA256.generateKey[MacErrorM]
    jwt             <- JWTMacImpure.build[HMACSHA256](impureClaims, key) //You can sign and build a jwt object directly
    verifiedFromObj <- JWTMacImpure.verifyFromInstance[HMACSHA256](jwt, key)
    stringjwt       <- JWTMacImpure.buildToString[HMACSHA256](impureClaims, key) //Or build it straight to string
    isverified      <- JWTMacImpure.verifyFromString[HMACSHA256](stringjwt, key) //You can verify straight from a string
    parsed          <- JWTMacImpure.verifyAndParse[HMACSHA256](stringjwt, key) //Or verify and return the actual instance
  } yield parsed
```