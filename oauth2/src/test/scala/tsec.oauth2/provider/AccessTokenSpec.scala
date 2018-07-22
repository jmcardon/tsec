package tsec.oauth2.provider

import java.time.Instant
import java.time.{ZoneOffset, ZonedDateTime}

import cats.effect.IO

import scala.concurrent.duration._
import org.scalatest.Matchers._
import org.scalatest._

class AccessTokenSpec extends FlatSpec {

  it should "say a token is active that is not yet expired" in {
    val token = AccessToken("token", None, None, lifeTime = Some(15 seconds), createdAt = Instant.now())
    token.isExpired[IO].unsafeRunSync() shouldBe false
  }

  it should "expire tokens that have a lifespan that has passed" in {
    val token = AccessToken(
      "token",
      None,
      None,
      lifeTime = Some(1798 seconds),
      createdAt = ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(1800).toInstant
    )
    token.isExpired[IO].unsafeRunSync() shouldBe true
  }

  it should "not expire tokens that have no lifespan" in {
    val token = AccessToken(
      "token",
      None,
      None,
      lifeTime = None,
      createdAt = ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(1800).toInstant
    )
    token.isExpired[IO].unsafeRunSync() shouldBe false
  }
}
