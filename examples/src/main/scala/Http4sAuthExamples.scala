import java.util.UUID

import cats._
import cats.data.OptionT
import cats.effect.{IO, Sync}
import org.http4s.HttpService
import tsec.authentication._
import tsec.authorization._
import tsec.cipher.symmetric.imports._

import scala.collection.mutable
import scala.concurrent.duration._
import org.http4s.dsl.io._


object Http4sAuthExamples {
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
  sealed abstract class Role(val roleRepr: String)
  object Role extends SimpleAuthEnum[Role, String] {
    implicit case object Administrator extends Role("Administrator")
    implicit case object Customer      extends Role("User")
    implicit case object Seller        extends Role("Seller")
    implicit case object CorruptedData extends Role("corrupted")

    implicit val E: Eq[Role]      = Eq.fromUniversalEquals[Role]
    val getRepr: (Role) => String = _.roleRepr

    protected val values: AuthGroup[Role] = AuthGroup(Administrator, Customer, Seller)
    val orElse: Role                      = CorruptedData
  }

  case class User(id: Int, age: Int, name: String, role: Role = Role.Customer)

  object User {
    implicit def authRole[F[_]](implicit F: MonadError[F, Throwable]): AuthorizationInfo[F, User, Role] =
      new AuthorizationInfo[F, User, Role] {
        def fetchInfo(u: User): F[Role] = F.pure(u.role)
      }
  }

  /*
  Here, we initialize our authenticator. For this, we need the following:
  1. Depending on your authenticator, you need either TSecCookieSettings or TSecJWTSettings
  2. Create a backing store for your identity. This could be using doobie, slick, whatever, so long as it conforms
  to the type signature and your effect type. I'd recommend doobie, simply because it's pretty great
  (Optional): If you want a backing store, you need a `BackingStore[F, UUID, ?] where ? is your authenticator type.
  3. Feed it into the authenticator you want
  4. Create a RequestAuthenticator
  5. Auth all the things!

  For our example, we'll use a dummy backing store with encrypted cookies and a cookie backing store
  We will encrypt our cookies with AES GCM.
  In this case, we need a cryptographic key to sign and encrypt our cookie
   */
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

  val onlyAdmins      = BasicRBAC[IO, User, Role](Role.Administrator, Role.Customer)
  val adminsAndSeller = BasicRBAC[IO, User, Role](Role.Administrator, Role.Seller)

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
      val r: SecuredRequest[IO, AuthEncryptedCookie[AES128, Int], User] = request
      Ok()
  }

  /*
  For an endpoint with different authorization logic, we can use:
   */
  val authorizedService: HttpService[IO] = Auth.authorized(onlyAdmins) {
    case request @ GET -> Root / "api" asAuthed user =>
      Ok(user.role.roleRepr)
  }

}
