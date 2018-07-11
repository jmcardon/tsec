package tsec.oauth2.provider

import cats.syntax.either._
import org.scalatest.FlatSpec
import org.scalatest.Matchers._

class ValidatedRequestSpec extends FlatSpec {
  it should "fetch Basic64" in {
    val c = ValidatedRequest.parseClientCredential(Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")), Map.empty).toOption.get
    c.clientId should be("client_id_value")
    c.clientSecret should be(Some("client_secret_value"))
  }

  it should "fetch Basic64 by case insensitive" in {
    val headers = Map("authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU="))
    val c = ValidatedRequest.parseClientCredential(headers, Map.empty).toOption.get
    c.clientId should be("client_id_value")
    c.clientSecret should be(Some("client_secret_value"))
  }

  it should "fetch authorization header without colon" in {
    val parsedCred = ValidatedRequest.parseClientCredential(Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVl")), Map.empty)
    parsedCred.isLeft shouldBe true
  }

  it should "fetch empty client_secret with colon" in {
    val c       = ValidatedRequest.parseClientCredential(Map("Authorization" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOg==")), Map.empty).toOption.get
    c.clientId should be("client_id_value")
    c.clientSecret should be(None)
  }

  it should "not fetch not Authorization key in header" in {
    val c = ValidatedRequest.parseClientCredential(Map("authorizatio" -> Seq("Basic Y2xpZW50X2lkX3ZhbHVlOmNsaWVudF9zZWNyZXRfdmFsdWU=")), Map.empty)
    c should be(Left(InvalidClient(s"Failed to parse client credential from header (Missing authorization header) and params")))
  }

  it should "not fetch invalid Base64" in {
    val parsedCred = ValidatedRequest.parseClientCredential(Map("Authorization" -> Seq("Basic basic")), Map.empty)
    parsedCred shouldBe Left(InvalidClient("Failed to parse client credential from header (invalid Base 64) and params"))
  }

  it should "fetch parameter" in {
    val c = ValidatedRequest.parseClientCredential(Map.empty, Map("client_id" -> Seq("client_id_value"), "client_secret" -> Seq("client_secret_value"))).toOption.get
    c.clientId should be("client_id_value")
    c.clientSecret should be(Some("client_secret_value"))
  }

  it should "omit client_secret" in {
    val c       = ValidatedRequest.parseClientCredential(Map.empty, Map("client_id" -> Seq("client_id_value"))).toOption.get
    c.clientId should be("client_id_value")
    c.clientSecret should be(None)
  }

  it should "not fetch missing parameter" in {
    val c       = ValidatedRequest.parseClientCredential(Map.empty, Map("client_secret" -> Seq("client_secret_value")))
    c should be(Left(InvalidClient("Failed to parse client credential from header (Missing authorization header) and params")))
  }

  it should "not fetch invalid parameter" in {
    val parsedCred = ValidatedRequest.parseClientCredential(Map("Authorization" -> Seq("")), Map.empty)
    parsedCred shouldBe Left(InvalidAuthorizationHeader)
  }

  it should "not fetch invalid Authorization header" in {
    val parsedCred = ValidatedRequest.parseClientCredential(Map("Authorization" -> Seq("Digest Y2xpZW50X2lkX3ZhbHVlOg==")), Map.empty)

    parsedCred shouldBe Left(InvalidAuthorizationHeader)
  }

  it should "not fetch if Authorization header is invalid, but client_id and client_secret are valid and present in parms" in {
    val parsedCred = ValidatedRequest.parseClientCredential(Map("Authorization" -> Seq("fakeheader aaaa")), Map("client_id"     -> Seq("client_id_value"), "client_secret" -> Seq("client_secret_value")))
    parsedCred shouldBe Left(InvalidAuthorizationHeader)
  }
}
