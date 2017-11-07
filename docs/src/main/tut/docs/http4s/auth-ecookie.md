---
layout: docs
number: 7
title: "Encrypted cookie auth"
---
# Encrypted cookie authentication

Encrypted cookie authenticator uses `TsecCookieSettings` for configuration:
```scala
  final case class TSecCookieSettings(
      cookieName: String = "tsec-auth-cookie",
      secure: Boolean,
      httpOnly: Boolean = true,
      domain: Option[String] = None,
      path: Option[String] = None,
      extension: Option[String] = None,
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration]
  )
```

This authenticator uses cookies as the underlying mechanism to track state, however, any information such as expiry, 
rolling window expiration or id is encrypted, as well as signed. This authenticator has both stateful and stateless modes.

* Choose between one of AES128, AES192 or AES256 to perform your Authenticated Encryption with AES-GCM. 
**Recommended default: AES128**.
* User and token backing store as stated above, or just User store for stateless authenticator
* Can be vulnerable to [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery), to be used with the CSRF middleware.
* [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) doesn't play nice with cookies.
* Your ID type for your user must have an `Encoder` and `Decoder` instance from circe

### Authenticator creation
If want want to create services, create a request handler as such:

```tut:silent
  import java.util.UUID
  import cats.effect.IO
  import examples.Http4sAuthExample._
  import examples.Http4sAuthExample.User._
  import examples.Http4sAuthExample.Role._
  import tsec.authentication._
  import tsec.authorization._
  import tsec.cipher.symmetric.imports._
  import org.http4s.HttpService
  import org.http4s.dsl.io._
  import scala.concurrent.duration._
  
  val cookieBackingStore: BackingStore[IO, UUID, AuthEncryptedCookie[AES128, Int]] =
      dummyBackingStore[IO, UUID, AuthEncryptedCookie[AES128, Int]](_.id)
  
    //We create a way to store our users. You can attach this to say, your doobie accessor
    val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)


  val settings: TSecCookieSettings = TSecCookieSettings(
    cookieName = "tsec-auth",
    secure = false,
    expiryDuration = 10.minutes, // Absolute expiration time
    maxIdle = None // Rolling window expiration. Set this to a Finiteduration if you intend to have one
  )

  val key: SecretKey[AES128] = AES128.generateKeyUnsafe() //Our encryption key

  val encryptedCookieAuth =
    EncryptedCookieAuthenticator.withBackingStore(
      settings,
      cookieBackingStore,
      userStore,
      key
    )

  val Auth =
    SecuredRequestHandler(encryptedCookieAuth)

  val onlyAdmins      = BasicRBAC[IO, Role, User, AuthEncryptedCookie[AES128, Int]](Role.Administrator, Role.Customer)
  val adminsAndSeller = BasicRBAC[IO, Role, User, AuthEncryptedCookie[AES128, Int]](Role.Administrator, Role.Seller)

  /*
  Now from here, if want want to create services, we simply use the following
  (Note: Since the type of the service is HttpService[IO], we can mount it like any other endpoint!):
   */
  val service: HttpService[IO] = Auth {
    //Where user is the case class User above
    case request @ GET -> Root / "api" asAuthed user =>
      /*
      Note: The request is of type: SecuredRequest, which carries:
      1. The request
      2. The Authenticator (i.e token)
      3. The identity (i.e in this case, User)
       */
      val r: SecuredRequest[IO, User, AuthEncryptedCookie[AES128, Int]] = request
      Ok()
  }

  /*
  For an endpoint with different authorization logic, we can use:
   */
  val authorizedService: HttpService[IO] = Auth.authorized(onlyAdmins) {
    case request @ GET -> Root / "api" asAuthed user =>
      Ok(user.role.roleRepr)
  }
```