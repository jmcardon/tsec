package tsec.authentication

import java.util.UUID

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

abstract class AuthenticatorSpec extends TestSpec with MustMatchers {

  protected [tsec] trait Embedder[F[_],E] {
    def embedIntoRequest(e: E, req: Request[F]): Request[F]
  }

  def embedIntoRequest[F[_], B](b: B, request: Request[F])(implicit embedder: Embedder[F, B]) = embedder.embedIntoRequest(b, request)

  def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: Monad[F]) = new BackingStore[F , I, V] {
    private val storageMap = mutable.HashMap.empty[I, V]

    def put(elem: V): F[Int] = {
      storageMap.put(getId(elem), elem)
      F.pure(1)
    }

    def get(id: I): OptionT[F, V] = {
      OptionT.fromOption[F](storageMap.get(id))
    }

    def update(v: V): F[Int] = {
      storageMap.update(getId(v), v)
      F.pure(1)
    }

    def delete(id: I): F[Int] = {
      storageMap.remove(id) match {
        case Some(_) => F.pure(1)
        case None => F.pure(0)
      }
    }
  }

  val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)

  def AuthenticatorTest[A](title: String, authenticator: AuthenticatorEV[IO, A, Int, DummyUser])(implicit embedder: Embedder[IO, authenticator.Authenticator[A]]) = {
    behavior of title
    val dummy1 = DummyUser(0)
    val dummy2 = DummyUser(1)

    it should "Create, embed properly" in {
      val results = (for {
        _ <- OptionT.liftF(dummyStore.put(dummy1))
        auth <- authenticator.create(dummy1.id)
        req2 <- authenticator.extractAndValidate(embedIntoRequest(auth, Request[IO]()))
        _ <- OptionT.liftF(dummyStore.delete(dummy1.id))
      } yield req2).value
      val extracted = results.unsafeRunSync()
      extracted.isEmpty mustBe false
      extracted.map(_.identity) mustBe Some(dummy1)
    }
  }

}
