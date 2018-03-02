package tsec.jwt

import java.time.Instant

import io.circe._
import io.circe.syntax._
import io.circe.parser._
import tsec.TestSpec

class JWTClaimsTest extends TestSpec {

  behavior of "JWTClaims"

  it should "not mutate the internal json tree" in {
    val claims1 = JWTClaims()
    val claims2 = claims1.withSubject("hi")

    claims1.subject mustBe None
    claims2.subject mustBe Some("hi")
  }

  it should "embed and retrieve a custom field correctly, without mutating" in {
    val claims1 = JWTClaims()
    val claims2 = claims1.withCustomField[Long]("hi", 30L)
    claims2.flatMap(_.getCustom[Long]("hi")) mustBe Right(30L)
    claims1.getCustom[Long]("hi") mustBe Left(DecodingFailure("No Such key", List()))
  }

  it should "Serialize and deserialize properly" in {
    val claims = JWTClaims(
      expiration = Some(Instant.now()),
      notBefore = Some(Instant.now()))
    decode[JWTClaims](claims.asJson.toString()) mustBe Right(claims)
  }

  it should "correctly deserialize the 'aud' field when it is a string literal" in {
    val representation = """
    {
      "jti": "1235",
      "aud": "localhost"
    }
    """
    val expectedClaims = JWTClaims(

    )
    decode[JWTClaims](representation).map(_.audience) mustBe Right(Some(JWTSingleAudience("localhost")))
  }

  it should "correctly deserialize the 'aud' field when it is a list of strings" in {
    val representation = """
    {
      "jti": "1235",
      "aud": ["localhost", "domain"]
    }
    """
    val expectedClaims = JWTClaims(

    )
    decode[JWTClaims](representation).map(_.audience) mustBe Right(Some(JWTListAudience(List("localhost", "domain"))))
  }

}
