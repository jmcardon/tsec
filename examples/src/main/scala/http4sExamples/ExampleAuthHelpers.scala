package http4sExamples

import cats._
import cats.data.OptionT
import cats.effect.{IO, Sync}
import http4sExamples.ExampleAuthHelpers.Role.{Administrator, Customer}
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
        case None => F.raiseError(new IllegalArgumentException)
      }
  }

  /*
  In our example, we will demonstrate how to use SimpleAuthEnum, as well as
  Role based authorization
   */
  sealed abstract case class Role(roleRepr: String)

  object Role extends SimpleAuthEnum[Role, String] {

    implicit object Administrator extends Role("Administrator")

    implicit object Customer extends Role("User")

    implicit object Seller extends Role("Seller")

    implicit object CorruptedData extends Role("corrupted")

    implicit val E: Eq[Role] = Eq.fromUniversalEquals[Role]
    val getRepr: (Role) => String = _.roleRepr

    protected val values: AuthGroup[Role] = AuthGroup(Administrator, Customer, Seller)
    val orElse: Role = CorruptedData
  }

  val AdminRequired: BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]] =
    BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]](Administrator)
  val CustomerRequired: BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]] =
    BasicRBAC[IO, Role, User, AugmentedJWT[HMACSHA256, Int]](Administrator, Customer)

  case class User(id: Int, age: Int, name: String, role: Role = Role.Customer)

  object User {
    implicit def authRole[F[_]](implicit F: MonadError[F, Throwable]): AuthorizationInfo[F, Role, User] =
      new AuthorizationInfo[F, Role, User] {
        def fetchInfo(u: User): F[Role] = F.pure(u.role)
      }
  }

}
