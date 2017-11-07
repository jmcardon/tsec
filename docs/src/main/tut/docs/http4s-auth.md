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
3. JWT using HS256, HS384 and HS512 (Stateless and Stateful)
4. Bearer Tokens using `SecureRandomId`

In general, to use an authenticator, you need:

1. A instance of `BackingStore[F[_], I, U]` for your User type, where I is the id type of your user type, 
and `U` is the user class.
2. An instance of either `TSecCookieSettings` or `TSecJWTSettings` based on the type of authenticator
3. Either a Signing Key or an Encryption Key, based on the kind of Authenticator
4. For Stateful Authenticators, you will require a `BackingStore[F, UUID, Token]` where `Token` is the
Token type.

Also please, for your sanity and ours **use TLS in prod**.

### Examples Setup

Note: This class is the setup to our authentication and authorization examples
```scala
package examples

import cats._
import cats.data.OptionT
import cats.effect.Sync
import org.http4s.HttpService
import org.http4s.dsl.io._
import tsec.authentication._
import tsec.authorization._
import tsec.cipher.symmetric.imports._
import tsec.common.SecureRandomId
import tsec.jws.mac.JWTMac
import tsec.mac.imports._

import scala.collection.mutable
import scala.concurrent.duration._

object Http4sAuthExample {
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
  sealed abstract case class Role(roleRepr: String)
  object Role extends SimpleAuthEnum[Role, String] {
    implicit object Administrator extends Role("Administrator")
    implicit object Customer      extends Role("User")
    implicit object Seller        extends Role("Seller")
    implicit object CorruptedData extends Role("corrupted")

    implicit val E: Eq[Role]      = Eq.fromUniversalEquals[Role]
    val getRepr: (Role) => String = _.roleRepr

    protected val values: AuthGroup[Role] = AuthGroup(Administrator, Customer, Seller)
    val orElse: Role                      = CorruptedData
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
* Great for applications where security is not a deathly priority and long-lived sessions are desireable.

Cons:
* Your security is as strong as the underlying crypto primitive. There's no extra safety: You cannot cross check without
any record of the tokens you have.
* You can only invalidate using an explicit blacklist, which you would have to roll out as a middleware. If you need this
dynamically updated, it will increase the network throughput.
