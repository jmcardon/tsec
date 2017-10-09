package tsec.authentication

import cats.data.OptionT
import cats.effect.IO
import cats.{Id, Monad}
import tsec.TestSpec
import org.http4s._
import org.http4s.dsl._
import cats.syntax.all._
import org.scalatest.MustMatchers

import scala.collection.mutable

case class DummyUser(id: Int, name: String = "bob")

/**
  * An inner class for defining tests against an authenticator
  *
  * @param authie
  * @tparam A
  * @tparam Authenticator
  */
protected[authentication] abstract case class AuthSpecTester[A, Authenticator[_]](
    authie: AuthenticatorEV[IO, A, Int, DummyUser, Authenticator]
) {

  def embedInRequest(request: Request[IO], authenticator: Authenticator[A]): Request[IO]

  def extractFromResponse(response: Response[IO]): OptionT[IO, Authenticator[A]]

  def expireAuthenticator(b: Authenticator[A]): OptionT[IO, Authenticator[A]]

  def timeoutAuthenticator(b: Authenticator[A]): OptionT[IO, Authenticator[A]]

  def wrongKeyAuthenticator: OptionT[IO, Authenticator[A]]
}

abstract class AuthenticatorSpec[B[_]] extends TestSpec with MustMatchers {

  def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: Monad[F]) = new BackingStore[F, I, V] {
    private val storageMap = mutable.HashMap.empty[I, V]

    def put(elem: V): F[Int] = {
      storageMap.put(getId(elem), elem)
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

  val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)

  def AuthenticatorTest[A](title: String, authSpec: AuthSpecTester[A, B]) = {
    behavior of title
    val dummy1 = DummyUser(0)

    it should "Create, embed and extract properly" in {
      val results = (for {
        _            <- OptionT.liftF(dummyStore.put(dummy1))
        auth         <- authSpec.authie.create(dummy1.id)
        fromRequest  <- authSpec.authie.extractAndValidate(authSpec.embedInRequest(Request[IO](), auth))
        res          <- OptionT.pure[IO](authSpec.authie.embed(Response[IO](), fromRequest.authenticator))
        fromResponse <- authSpec.extractFromResponse(res)
      } yield (fromResponse, fromRequest)).value
      val extracted = results.unsafeRunSync()
      extracted.isEmpty mustBe false
      extracted.map(_._2.identity) mustBe Some(dummy1)
      extracted.map(_._1) mustBe extracted.map(_._2.authenticator)
    }

    it should "refresh properly" in {
      val results = (for {
        auth     <- authSpec.authie.create(dummy1.id)
        expired  <- authSpec.timeoutAuthenticator(auth)
        updated1 <- authSpec.authie.update(expired)
        renewed  <- authSpec.authie.renew(updated1)
        req2     <- authSpec.authie.extractAndValidate(authSpec.embedInRequest(Request[IO](), renewed))
      } yield req2).value
      val extracted = results.unsafeRunSync()
      extracted.isEmpty mustBe false
    }

    it should "Not validate for an expired token" in {
      val results = (for {
        auth    <- authSpec.authie.create(dummy1.id)
        expired <- authSpec.expireAuthenticator(auth)
        updated <- authSpec.authie.update(expired)
        req2    <- authSpec.authie.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
      } yield req2).value
      val extracted = results.unsafeRunSync()
      extracted.isEmpty mustBe true
    }

    it should "Not validate for a token past the timeout" in {
      val results = (for {
        auth    <- authSpec.authie.create(dummy1.id)
        expired <- authSpec.timeoutAuthenticator(auth)
        updated <- authSpec.authie.update(expired)
        req2    <- authSpec.authie.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
      } yield req2).value
      val extracted = results.unsafeRunSync()
      extracted.isEmpty mustBe true
    }

    it should "Not validate for a token with a different key/incorrect" in {
      val results = (for {
        wrong <- authSpec.wrongKeyAuthenticator
        req2  <- authSpec.authie.extractAndValidate(authSpec.embedInRequest(Request[IO](), wrong))
      } yield req2).value
      val extracted = results.unsafeRunSync()
      extracted.isEmpty mustBe true
    }

    it should "discard a token properly" in {
      val results = (for {
        auth     <- authSpec.authie.create(dummy1.id)
        discarded  <- authSpec.authie.discard(auth)
        req2     <- authSpec.authie.extractAndValidate(authSpec.embedInRequest(Request[IO](), discarded))
      } yield req2).value
      val extracted = results.unsafeRunSync()
      extracted.isEmpty mustBe true
    }
  }

}
