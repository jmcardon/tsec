---
layout: docs
number: 12
title: "Composing Authenticators"
---

# Composing Authenticators

Since `0.0.1-M5`, all `Authenticators` have a common interface:

```scala
trait Authenticator[I] {
  val identity: I
  val expiry: Instant
  val lastTouched: Option[Instant]

  def isExpired(now: Instant): Boolean = expiry.isBefore(now)
  def isTimedout(now: Instant, timeOut: FiniteDuration): Boolean =
    lastTouched.exists(
      _.plusSeconds(timeOut.toSeconds)
        .isBefore(now)
    )
}
```

However, authenticators themselves tend to vary very differently in structure. The structure `AugmentedJWT` implements
this auth is different to a `TSecBearerToken`.

This means that, in the case that you must use different token types for a particular endpoint,
you can choose to compose authenticators, at the cost of losing a tad bit of type information.

As an example, let's bring in different types of authenticators:

```tut:silent
import cats.data.OptionT
import cats.effect.IO
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.{Authorization => H4SA}
import tsec.common.SecureRandomId
import tsec.jws.mac.JWTMac
import tsec.mac.imports.HMACSHA256
import tsec.authentication._

case class DummyUser(id: Int, name: String = "bob")

def jwtAuthenticator: StatefulJWTAuthenticator[IO, Int, DummyUser, HMACSHA256] = ???

def bearerTokenAuthenticator: BearerTokenAuthenticator[IO, Int, DummyUser] = ???

def cookieAuthenticator: SignedCookieAuthenticator[IO, Int, DummyUser, HMACSHA256] = ???

```

From here, we can compose them using the method `foldAuthenticate`:

```tut
/** This turns into a function TSecAuthService => HttpService **/
def folded = jwtAuthenticator.foldAuthenticate(bearerTokenAuthenticator, cookieAuthenticator) _
```

We can then apply it over a service that takes an `Authenticator[I]`

```tut:silent
  val service: TSecAuthService[IO, DummyUser, Authenticator[Int]] = TSecAuthService {
    case GET -> Root asAuthed _ =>
      Ok()
  }
```
```tut
def myService: HttpService[IO] = folded(service)
```

What this does, is that it will try to retrieve the raw format of the first authenticator. i.e, a bearer token string,
or a custom header. If it finds it, it will try to authenticate, or reject. If it is not present, it will try
extracting the raw format of the second authenticator: so on and so forth.

## Advanced


This is possible because `AuthenticatorService` has these two methods:

```scala
  /** Attempt to retrieve the raw representation of an A
    * This is primarily useful when attempting to combine AuthenticatorService,
    * to be able to evaluate an endpoint with more than one token type.
    * or simply just to prod whether the request is malformed.
    *
    * @return
    */
  def extractRawOption(request: Request[F]): Option[String]

  /** Parse the raw representation from `extractRawOption`
    *
    */
  def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, A]]
```

In the default case, anything that yields a `Some[String]` for `extractRawOption` will attempt to authenticate. If
you need anything more complicated, please refer to the `foldAuthenticate` method in `Authenticator` for a 
reference on how this has to be implemented (it requires an upcast, given Kleisli and Authenticator are invariants, but
such an upcast is correct so long as you only intend to use it to lose information, not to parse an incorrect token
type with it).