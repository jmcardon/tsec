package tsec.jwt

import java.time.Instant

import cats.syntax.either._
import io.circe._
import io.circe.parser._
import io.circe.syntax._
import io.circe.generic.auto.`package`._
import tsec.TestSpec

class JWTClaimsTest extends TestSpec {

  case class Custom(a: String, b: Int, d: Double)

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

  it should "embed and retrieve a top level custom object" in {
    val customObject = Custom("hello", 2, 3.14)
    val claims1      = JWTClaims(customFields = customObject.asJsonObject.toList)

    claims1.as[Custom] mustBe Right(customObject)
  }

  it should "Serialize and deserialize properly" in {
    val claims = JWTClaims(expiration = Some(Instant.now()), notBefore = Some(Instant.now()))
    decode[JWTClaims](claims.asJson.toString()) mustBe Right(claims)
  }

  it should "correctly deserialize the 'aud' field when it is a string literal" in {
    val representation = """
    {
      "jti": "1235",
      "aud": "localhost"
    }
    """
    decode[JWTClaims](representation).map(_.audience) mustBe Right(Some(JWTSingleAudience("localhost")))
  }

  it should "correctly deserialize the 'aud' field when it is a list of strings" in {
    val representation = """
    {
      "jti": "1235",
      "aud": ["localhost", "domain"]
    }
    """
    decode[JWTClaims](representation).map(_.audience) mustBe Right(Some(JWTListAudience(List("localhost", "domain"))))
  }

}
