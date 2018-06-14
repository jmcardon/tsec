package tsec.oauth2.provider

import java.time.{ZoneOffset, ZonedDateTime}
import java.util.Date
import scala.concurrent.duration._
import org.scalatest.Matchers._
import org.scalatest._

class AccessTokenSpec extends FlatSpec {

  it should "say a token is active that is not yet expired" in {
    val token = AccessToken("token", None, None, life = Some(15 seconds), createdAt = new Date())
    token.isExpired shouldBe false
  }

  it should "expire tokens that have a lifespan that has passed" in {
    val token = AccessToken(
      "token",
      None,
      None,
      life = Some(1798 seconds),
      createdAt = Date.from(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(1800).toInstant)
    )
    token.isExpired shouldBe true
  }

  it should "not expire tokens that have no lifespan" in {
    val token = AccessToken(
      "token",
      None,
      None,
      life = None,
      createdAt = Date.from(ZonedDateTime.now(ZoneOffset.UTC).minusSeconds(1800).toInstant)
    )
    token.isExpired shouldBe false
  }
}
