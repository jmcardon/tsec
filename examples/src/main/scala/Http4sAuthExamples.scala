import java.util.UUID

import Http4sAuthExamples.Role.{Administrator, Customer, Seller}
import cats.{Eq, Monad}
import cats.data.OptionT
import cats.effect.IO
import org.http4s.HttpService
import tsec.authentication._
import tsec.cipher.symmetric.imports.{AES128, SecretKey}

import scala.concurrent.duration._
import scala.collection.mutable
import org.http4s.dsl.io._
import tsec.authorization.{AuthGroup, AuthorizationInfo, BasicRBAC, SimpleAuthEnum}

object Http4sAuthExamples {
  def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: Monad[F]) = new BackingStore[F, I, V] {
    private val storageMap = mutable.HashMap.empty[I, V]

    def put(elem: V): F[Int] = {
      val map = storageMap.put(getId(elem), elem)
      if (map.isEmpty)
        F.pure(0)
      else
        F.pure(1)
    }

    def get(id: I): OptionT[F, V] =
      OptionT.fromOption[F](storageMap.get(id))

    def update(v: V): F[Int] = {
      storageMap.update(getId(v), v)
      F.pure(1)
    }

    def delete(id: I): F[Int] =
      storageMap.remove(id) match {
        case Some(_) => F.pure(1)
        case None    => F.pure(0)
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
    implicit val authRole: AuthorizationInfo[User, Role] = new AuthorizationInfo[User, Role] {
      def getRole(u: User): Role = u.role
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
    RequestHandler.encryptedCookie(encryptedCookieAuth)

  val onlyAdmins      = BasicRBAC[User, Role](Administrator, Customer)
  val adminsAndSeller = BasicRBAC[User, Role](Administrator, Seller)

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
  val authorizedService: HttpService[IO] = Auth.authorized(onlyAdmins){
    case request @ GET -> Root / "api" asAuthed user =>
      Ok(user.role.roleRepr)
  }


}
