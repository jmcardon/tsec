---
layout: docs
number: 6
title: "Overview"
---

# Http4s Authentication and Authorization

For Http4s Authentication, we provide token-based authentication which is either 
Stateless (No need for a  backing store) or Stateful(Requires backing store), through the following options:

1. Signed Cookie Authentication (Stateful)
2. Encrypted and Signed Cookie Authentication (Stateless and Stateful)
3. JWT using HS256, HS384 and HS512 (Stateless and Stateful, unencrypted and encrypted user IDs)
4. Bearer Tokens using `SecureRandomId`

In general, to use an authenticator, you need:

1. A instance of `BackingStore[F[_], I, U]` for your User type, where I is the id type of your user type, 
and `U` is the user class.
2. An instance of either `TSecCookieSettings` or `TSecJWTSettings` based on the type of authenticator
3. Either a Signing Key or an Encryption Key, based on the kind of Authenticator
4. For Stateful Authenticators, you will require a `BackingStore[F, Id, Token]` where `Token` is the
Token type, and `Id` is the authenticator Id type, which may vary

Also please, for your sanity and ours **use TLS in prod**.

## Examples Setup

Note: This class is the setup to our authentication and authorization examples


```tut:silent
import java.util.UUID

import cats._
import cats.data.OptionT
import cats.effect.{IO, Sync}
import cats.implicits._
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.authorization._
import tsec.cipher.symmetric.jca._
import tsec.common.SecureRandomId
import tsec.jws.mac.JWTMac

import scala.collection.mutable
import scala.concurrent.duration._


object ExampleAuthHelpers {
  def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: Sync[F]) = new BackingStore[F, I, V] {
    private val storageMap = mutable.HashMap.empty[I, V]

    def put(elem: V): F[V] = {
      val map = storageMap.put(getId(elem), elem)
      if (map.isEmpty)
        F.pure(elem)
      else
        F.raiseError(new IllegalArgumentException)
    }

    def get(id: I): OptionT[F, V] =
      OptionT.fromOption[F](storageMap.get(id))

    def update(v: V): F[V] = {
      storageMap.update(getId(v), v)
      F.pure(v)
    }

    def delete(id: I): F[Unit] =
      storageMap.remove(id) match {
        case Some(_) => F.unit
        case None    => F.raiseError(new IllegalArgumentException)
      }
  }

  /*
  In our example, we will demonstrate how to use SimpleAuthEnum, as well as
  Role based authorization
   */
  sealed case class Role(roleRepr: String)

  object Role extends SimpleAuthEnum[Role, String] {

    val Administrator: Role = Role("Administrator")
    val Customer: Role      = Role("User")
    val Seller: Role        = Role("Seller")

    implicit val E: Eq[Role] = Eq.fromUniversalEquals[Role]

    def getRepr(t: Role): String = t.roleRepr

    protected val values: AuthGroup[Role] = AuthGroup(Administrator, Customer, Seller)
  }

  case class User(id: Int, age: Int, name: String, role: Role = Role.Customer)

  object User {
    implicit def authRole[F[_]](implicit F: MonadError[F, Throwable]): AuthorizationInfo[F, Role, User] =
      new AuthorizationInfo[F, Role, User] {
        def fetchInfo(u: User): F[Role] = F.pure(u.role)
      }
  }
}
```

## Authenticating Services

A service with some token-based Authentication, be it cookie, jwt, bearer token, etc
requires two things: A Identity, for example our `User` type, and the type of AuthenticatorService you are using. We need a way to
both extract and validate the Authenticator, as well as extract the identity type. Here is where `TSec` authenticators 
shine, as this is their exact function.

Let's make an example with [BearerTokenAuthenticator](https://github.com/jmcardon/tsec/blob/master/examples/src/main/scala/http4sExamples/BearerTokenExample.scala) from scratch:

```tut:silent

 import ExampleAuthHelpers._ // import dummyBackingStore factory
 
  val bearerTokenStore =
      dummyBackingStore[IO, SecureRandomId, TSecBearerToken[Int]](s => SecureRandomId.coerce(s.id))

  //We create a way to store our users. You can attach this to say, your doobie accessor
    val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)
  
    val settings: TSecTokenSettings = TSecTokenSettings(
      expiryDuration = 10.minutes, //Absolute expiration time
      maxIdle = None
    )
    
    val bearerTokenAuth =
        BearerTokenAuthenticator(
          bearerTokenStore,
          userStore,
          settings
    )
```

From here, we can create a `SecureRequestHandler`, which detecting whether it is
rolling window or not.


```tut
  val Auth =
    SecuredRequestHandler(bearerTokenAuth)
```

Then, we can use our `TSecAuthService`:

```tut:silent
 val authservice: TSecAuthService[TSecBearerToken[Int], User, IO] = TSecAuthService {
     case GET -> Root asAuthed user =>
       Ok()
   }
 
   /*
   Now from here, if want want to create services, we simply use the following
   (Note: Since the type of the service is HttpService[IO], we can mount it like any other endpoint!):
    */
   val service: HttpService[IO] = Auth.liftService(TSecAuthService {
     //Where user is the case class User above
     case request@GET -> Root / "api" asAuthed user =>
       /*
       Note: The request is of type: SecuredRequest, which carries:
       1. The request
       2. The Authenticator (i.e token)
       3. The identity (i.e in this case, User)
        */
       val r: SecuredRequest[IO, User, TSecBearerToken[Int]] = request
       Ok()
   })
```

In essence, this is captured by `SecuredRequestHandler`, which wraps the process of having to create the service
and the middleware for you in a simple `apply` method, so you only have to worry about creating the route. See the examples
on specific authenticators for more.

## Stateful vs Stateless

**Stateful:**

Pros:
* Better Security on top of the security the cryptographic primitives give you. Stateful tokens are cross-checked with 
what is in your backing store.
* Easy to invalidate: Simply remove one from your backing store! it will not pass the authentication check if it is not there.

Cons:
* Requires a backing store that can deal with concurrent updates. Thus, it must be synchronized.
* Will have possibly higher network throughput, if your token store is outside of application memory.

**Stateless**

Pros:
* Less network throughput. No need to use a backing store.
* Great for applications where security is not a deathly priority and long-lived sessions are desirable.

Cons:
* Your security is as strong as the underlying crypto primitive. There's no extra safety: You cannot cross check without
any record of the tokens you have.
* You can only invalidate using an explicit blacklist, which you would have to roll out as a middleware. If you need this
dynamically updated, it will increase the network throughput.
