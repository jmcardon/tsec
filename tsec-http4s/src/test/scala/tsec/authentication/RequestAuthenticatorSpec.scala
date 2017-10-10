package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT

import cats.effect.IO
import io.circe.Json
import org.http4s.dsl.io._
import org.http4s.circe._
import tsec.cipher.symmetric.imports._
import tsec.authentication._
import org.http4s._
import io.circe.syntax._
import io.circe.generic.auto._
import cats.syntax.all._
import org.http4s.util.CaseInsensitiveString
import io.circe.parser.parse

class RequestAuthenticatorSpec[B[_]] extends AuthenticatorSpec[B] {

  def RequestAuthTests[A](title: String, authSpec: AuthSpecTester[A, B]) {

    behavior of "SecuredRequests: " + title

    val dummyBob = DummyUser(0)

    val requestAuth: RequestAuthenticator[IO, A, Int, DummyUser, B] = RequestAuthenticator(authSpec.authie)

    //Add bob to the db
    dummyStore.put(dummyBob).unsafeRunSync()

    val testService: HttpService[IO] = requestAuth {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
    }

    it should "Return a proper deserialized user" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- requestAuth.authenticator.create(dummyBob.id)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(
        dummyBob
      )
    }

    it should "fail on an expired token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth    <- requestAuth.authenticator.create(dummyBob.id)
        expired <- authSpec.expireAuthenticator(auth)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), expired)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .map(_.status)
        .unsafeRunSync() mustBe Status.Forbidden
    }

    it should "work on a renewed token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth    <- requestAuth.authenticator.create(dummyBob.id)
        expired <- authSpec.expireAuthenticator(auth)
        renewed <- authSpec.authie.renew(expired)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(
        dummyBob
      )
    }

    it should "fail on a timed out token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth     <- requestAuth.authenticator.create(dummyBob.id)
        timedOut <- authSpec.timeoutAuthenticator(auth)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), timedOut)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .map(_.status)
        .unsafeRunSync() mustBe Status.Forbidden
    }

    it should "work on a refreshed token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth    <- requestAuth.authenticator.create(dummyBob.id)
        expired <- authSpec.timeoutAuthenticator(auth)
        renewed <- authSpec.authie.refresh(expired)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(
        dummyBob
      )
    }

    it should "Reject an invalid token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- authSpec.wrongKeyAuthenticator
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response.getOrElse(Response[IO](status = Status.Forbidden)).map(_.status).unsafeRunSync() mustBe Status.Forbidden
    }

    it should "Fail on a discarded token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- requestAuth.authenticator.create(dummyBob.id)
        discarded    <- requestAuth.authenticator.discard(auth)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), discarded)
        res <- testService(embedded)
      } yield res
      response.getOrElse(Response[IO](status = Status.Forbidden)).map(_.status).unsafeRunSync() mustBe Status.Forbidden
    }
  }

}
