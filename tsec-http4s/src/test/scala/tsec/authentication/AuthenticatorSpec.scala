package tsec.authentication

import cats.data.OptionT
import cats.effect.IO
import cats.{Eq, Id, Monad}
import tsec.TestSpec
import org.http4s._
import org.http4s.dsl._
import cats.implicits._
import org.scalacheck._
import org.scalatest.{BeforeAndAfterEach, MustMatchers}
import org.scalatest.prop.PropertyChecks
import tsec.authorization.{AuthGroup, AuthorizationInfo, SimpleAuthEnum}

import scala.collection.mutable

sealed abstract case class DummyRole(repr: String)
object DummyRole extends SimpleAuthEnum[DummyRole, String] {
  implicit object Admin extends DummyRole("Admin")
  implicit object Other extends DummyRole("Other")
  implicit object Err   extends DummyRole("Err")

  val getRepr: (DummyRole) => String         = _.repr
  protected val values: AuthGroup[DummyRole] = AuthGroup(Admin, Other)
  val orElse: DummyRole                      = Err
}

case class DummyUser(id: Int, name: String = "bob", role: DummyRole = DummyRole.Other)

object DummyUser {
  implicit val role: AuthorizationInfo[IO, DummyUser, DummyRole] = new AuthorizationInfo[IO, DummyUser, DummyRole] {
    def fetchInfo(u: DummyUser): IO[DummyRole] = IO.pure(u.role)
  }
}

/** An inner class for defining tests against an authenticator
  * This contains utilities that are not present currently under the `Authenticator`
  * class that are necessary for testing.
  *
  * @tparam A
  */
protected[authentication] abstract case class AuthSpecTester[A, Auth[_]](
    auth: Authenticator[IO, A, Int, DummyUser, Auth],
    dummyStore: BackingStore[IO, Int, DummyUser]
) {

  def embedInRequest(request: Request[IO], authenticator: Auth[A]): Request[IO]

  def expireAuthenticator(b: Auth[A]): OptionT[IO, Auth[A]]

  def timeoutAuthenticator(b: Auth[A]): OptionT[IO, Auth[A]]

  def wrongKeyAuthenticator: OptionT[IO, Auth[A]]
}

abstract class AuthenticatorSpec[B[_]] extends TestSpec with MustMatchers with PropertyChecks with BeforeAndAfterEach {

  implicit val genDummy: Arbitrary[DummyUser] = Arbitrary(for {
    i <- Gen.chooseNum[Int](0, Int.MaxValue)
    s <- Gen.alphaNumStr
  } yield DummyUser(i, s))

  def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: Monad[F]) = new BackingStore[F, I, V] {
    val storageMap = mutable.HashMap.empty[I, V]

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

    def dAll(): Unit = storageMap.clear()
  }

  def AuthenticatorTest[A](title: String, authSpec: AuthSpecTester[A, B]) = {
    behavior of title

    it should "Create, embed and extract properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _            <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth         <- authSpec.auth.create(dummy1.id)
          fromRequest  <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), auth))
          _            <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield fromRequest)
          .handleErrorWith(_ => OptionT.none)
          .value

        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
        extracted.map(_.identity) mustBe Some(dummy1)
      }
    }

    it should "Not validate for an expired token" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _       <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth    <- authSpec.auth.create(dummy1.id)
          expired <- authSpec.expireAuthenticator(auth)
          updated <- authSpec.auth.update(expired)
          req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
          _       <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    it should "renew properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _        <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth     <- authSpec.auth.create(dummy1.id)
          expired  <- authSpec.expireAuthenticator(auth)
          updated1 <- authSpec.auth.update(expired)
          renewed  <- authSpec.auth.renew(updated1)
          req2     <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), renewed))
          _        <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
      }
    }

    it should "Not validate for a token past the timeout" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _       <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth    <- authSpec.auth.create(dummy1.id)
          expired <- authSpec.timeoutAuthenticator(auth)
          updated <- authSpec.auth.update(expired)
          req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
          _       <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    it should "refresh properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _        <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth     <- authSpec.auth.create(dummy1.id)
          expired  <- authSpec.timeoutAuthenticator(auth)
          updated1 <- authSpec.auth.update(expired)
          renewed  <- authSpec.auth.refresh(updated1)
          req2     <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), renewed))
          _        <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
      }
    }

    it should "Not validate for a token with a different key/incorrect" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _     <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          wrong <- authSpec.wrongKeyAuthenticator
          req2  <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), wrong))
          _     <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    it should "discard a token properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _         <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth      <- authSpec.auth.create(dummy1.id)
          discarded <- authSpec.auth.discard(auth)
          req2      <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), discarded))
          _         <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }
  }

}
