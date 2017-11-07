---
layout: docs
number: 11
title: "CSRF prevention"
---

# CSRF Prevention

[CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) attacks have been losing popularity over
the past years, but they are still no joke. If you are using any cookie-based authentication, or any sort of authentication
wherein you are _not_ sending your authentication in a custom header, this concerns you.

Fortunately, TSec provides a simple CSRF prevention middleware.

In short, to guard against this vulnerability, all you need to do is use the middleware to set the token cookie, and
send such a token along with a custom header value. Given that an attacker forging a request cannot access the values
of a cookie due to same-origin policy, this simple mechanism will guard against `CSRF`.

All you need to use the CSRF middleware for tsec is:

* An `F: Sync` 
* Choose between one of HMACSHA1, HMACSHA256, HMACSHA384 or HMACSHA512. **Recommended default: HMACSHA1, or 256**.
* A MacSigningKey
* An endpoint where you can give a token to a user, either by default using `withNewToken` or directly into the response
using `embed`


A truncated signature of the class looks like this:
```scala
final case class TSecCSRF[F[_]: Sync, A: MacTag: ByteEV](
    key: MacSigningKey[A],
    headerName: String = "X-TSec-Csrf",
    cookieName: String = "tsec-csrf",
    tokenLength: Int = 16,
    clock: Clock = Clock.systemUTC()
)
```

The `apply` method on this new class is of type:

```scala
type CSRFMiddleware[F[_]] =
    Middleware[OptionT[F, ?], Request[F], Response[F], Request[F], Response[F]]
```

Thus, you can use it as such:

```tut
  import cats.effect.IO
  import tsec.mac.imports._
  import cats.syntax.all._
  import tsec.csrf.TSecCSRF
  import org.http4s._
  import org.http4s.dsl.io._

  val newKey = HMACSHA256.generateKeyUnsafe()
  val tsecCSRF = TSecCSRF[IO, HMACSHA256](newKey)

  val dummyService: HttpService[IO] = tsecCSRF.withNewToken(HttpService[IO] {
    case GET -> Root =>
      Ok()
  }) // This endpoint now provides a user with a new csrf token.
  
  val dummyService2: HttpService[IO] = tsecCSRF.apply(HttpService[IO] {
    case GET -> Root / "hi" =>
      Ok()
  })//This endpoint is csrf checked

```