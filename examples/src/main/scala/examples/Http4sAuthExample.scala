package examples

import java.util.UUID

import cats._
import cats.data.OptionT
import cats.effect.{IO, Sync}
import examples.Http4sAuthExample.{User, dummyBackingStore}
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

object EncryptedCookieExample {

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

  val authWithBackingStore = //Instantiate a stateful authenticator
    EncryptedCookieAuthenticator.withBackingStore(
      settings,
      cookieBackingStore,
      userStore,
      key
    )

  val stateless = //Instantiate a stateless authenticator
    EncryptedCookieAuthenticator.stateless(
      settings,
      userStore,
      key
    )

  val Auth =
    SecuredRequestHandler(stateless)

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

}

object CookieAuthExample {

  val cookieBackingStore: BackingStore[IO, UUID, AuthenticatedCookie[HMACSHA256, Int]] =
    dummyBackingStore[IO, UUID, AuthenticatedCookie[HMACSHA256, Int]](_.id)

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val settings: TSecCookieSettings = TSecCookieSettings(
    cookieName = "tsec-auth",
    secure = false,
    expiryDuration = 10.minutes, // Absolute expiration time
    maxIdle = None // Rolling window expiration. Set this to a Finiteduration if you intend to have one
  )

  val key: MacSigningKey[HMACSHA256] = HMACSHA256.generateKeyUnsafe() //Our Signing key. Instantiate in a safe way using GenerateLift

  val cookieAuth =
    CookieAuthenticator(
      settings,
      cookieBackingStore,
      userStore,
      key
    )

  val Auth =
    SecuredRequestHandler(cookieAuth)

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
      val r: SecuredRequest[IO, User, AuthenticatedCookie[HMACSHA256, Int]] = request
      Ok()
  }

}

object JWTAuthExample {
  val jwtStore =
    dummyBackingStore[IO, SecureRandomId, JWTMac[HMACSHA256]](s => SecureRandomId.coerce(s.id))

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val settings: TSecJWTSettings = TSecJWTSettings(
    expirationTime = 10.minutes, //Absolute expiration time
    maxIdle = None
  )

  val signingKey: MacSigningKey[HMACSHA256] = HMACSHA256.generateKeyUnsafe() //Our signing key. Instantiate in a safe way using GenerateLift
  val encryptionKey: SecretKey[AES128] = AES128.generateKeyUnsafe() //Our encryption key. Instantiate in a safe way using GenerateLift

  val jwtStatelessauth =
    JWTAuthenticator.withBackingStore(
      settings,
      jwtStore,
      userStore,
      signingKey,
      encryptionKey
    )

  val Auth =
    SecuredRequestHandler(jwtStatelessauth)

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
      val r: SecuredRequest[IO, User, JWTMac[HMACSHA256]] = request
      Ok()
  }
}

object BearerTokenAuthExample {
  val bearerTokenStore =
    dummyBackingStore[IO, SecureRandomId, TSecBearerToken[Int]](s => SecureRandomId.coerce(s.id))

  //We create a way to store our users. You can attach this to say, your doobie accessor
  val userStore: BackingStore[IO, Int, User] = dummyBackingStore[IO, Int, User](_.id)

  val settings: TSecTokenSettings = TSecTokenSettings(
    expirationTime = 10.minutes, //Absolute expiration time
    maxIdle = None
  )

  val bearerTokenAuth =
    BearerTokenAuthenticator(
      bearerTokenStore,
      userStore,
      settings
    )

  val Auth =
    SecuredRequestHandler(bearerTokenAuth)

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
      val r: SecuredRequest[IO, User, TSecBearerToken[Int]] = request
      Ok()
  }
}
