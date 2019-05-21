package http4sExamples

import cats._
import cats.data.OptionT
import cats.effect.{IO, Sync}
import cats.instances.string._
import tsec.authentication._
import tsec.authorization._
import tsec.mac.jca.HMACSHA256

import scala.collection.mutable

object ExampleAuthHelpers {

  /** dummy factory for backing storage */
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

    protected val values: AuthGroup[Role] = AuthGroup(Administrator, Customer, Seller)
    override val orElse: Role             = Seller
    override val getRepr: Role => String  = _.roleRepr
  }

  import Role._

  val AdminRequired: BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]] =
    BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]](Administrator)
  val CustomerRequired: BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]] =
    BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]](Administrator, Customer)

  case class User(id: Int, age: Int, name: String, role: Role = Customer)

  object User {
    implicit def authRole[F[_]](implicit F: MonadError[F, Throwable]): AuthorizationInfo[F, Role, User] =
      new AuthorizationInfo[F, Role, User] {
        def fetchInfo(u: User): F[Role] = F.pure(u.role)
      }
  }

}
