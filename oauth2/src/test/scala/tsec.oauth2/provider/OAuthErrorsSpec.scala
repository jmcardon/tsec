package tsec.oauth2.provider

import org.scalatest.Matchers._
import org.scalatest._

class OAuthErrorsSpec extends FlatSpec {

  behavior of "OAuth Error Handling RFC 6749 Section 5.2"

  it should "produce a 400 status code for invalid_request" in {
    InvalidRequest("").statusCode should be(400)
  }

  it should "produce a 401 status code for invalid_client" in {
    InvalidClient("").statusCode should be(401)
  }

  it should "produce a 400 status code for invalid_grant" in {
    InvalidGrant("").statusCode should be(400)
  }

  it should "produce a 400 status code for unauthorized_client" in {
    UnauthorizedClient("").statusCode should be(400)
  }

  it should "produce a 400 status code for unsupported_grant_type" in {
    UnsupportedGrantType("").statusCode should be(400)
  }

  it should "produce a 400 status code for invalid_scope" in {
    InvalidScope("").statusCode should be(400)
  }

  it should "produce a 400 status code for redirect_uri_mismatch" in {
    val error = RedirectUriMismatch
    error.statusCode should be(400)
    error.errorType should be("invalid_request")
  }

  behavior of "OAuth Error Handling for Bearer Tokens RFC 6750 Section 3.1"

  it should "produce a 400 status code for invalid_request" in {
    InvalidRequest("").statusCode should be(400)
  }

  it should "produce a 401 status code for invalid_token" in {
    InvalidToken("").statusCode should be(401)
  }

  it should "produce a 403 status code for insufficient_scope" in {
    InsufficientScope("").statusCode should be(403)
  }
}
