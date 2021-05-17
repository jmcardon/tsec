package tsec.oauth2.provider

sealed abstract class OAuthError(val description: String) extends Exception(description) {
  def statusCode: Int
  def errorType: String
}

final case class RefreshTokenFailed(override val description: String)
    extends OAuthError(s"Failed to refresh token: $description") {
  val statusCode = 400
  val errorType  = "invalid_grant"
}

final case class FailedToIssueAccessToken(override val description: String)
    extends OAuthError(s"Failed to issue access token: $description") {
  val statusCode = 400
  val errorType  = "invalid_grant"
}

final case class FailedToDeleteAuthCode(override val description: String)
    extends OAuthError(s"Failed to delete auth code: $description") {
  val statusCode = 400
  val errorType  = "invalid_grant"
}

final case class InvalidRequest(override val description: String) extends OAuthError(description) {
  val statusCode = 400
  val errorType  = "invalid_request"
}

case object InvalidAuthorizationHeader extends OAuthError("invalid Authorization header") {
  val statusCode = 400
  val errorType  = "invalid_request"
}

final case class InvalidClient(override val description: String) extends OAuthError(description) {
  val statusCode = 401
  val errorType  = "invalid_client"
}

final case class UnauthorizedClient(override val description: String) extends OAuthError(description) {
  val statusCode = 400
  val errorType  = "unauthorized_client"
}

case object RedirectUriMismatch extends OAuthError("redirect uri mismatch") {
  val statusCode = 400
  val errorType  = "invalid_request"
}

final case class AccessDenied(override val description: String) extends OAuthError(description) {
  val statusCode = 401
  val errorType  = "access_denied"
}

final case class UnsupportedResponseType(override val description: String = "") extends OAuthError(description) {
  val statusCode = 400
  val errorType  = "unsupported_response_type"
}

final case class InvalidGrant(override val description: String = "") extends OAuthError(description) {
  val statusCode = 400
  val errorType  = "invalid_grant"
}

final case class UnsupportedGrantType(override val description: String = "") extends OAuthError(description) {
  val statusCode = 400
  val errorType  = "unsupported_grant_type"
}

final case class InvalidScope(override val description: String = "") extends OAuthError(description) {
  val statusCode = 400
  val errorType  = "invalid_scope"
}

final case class InvalidToken(override val description: String) extends OAuthError(description) {
  val statusCode = 401
  val errorType  = "invalid_token"
}

case object ExpiredToken extends OAuthError("The access token expired") {
  val statusCode = 401
  val errorType  = "invalid_token"
}

final case class InsufficientScope(override val description: String = "") extends OAuthError(description) {
  val statusCode = 403
  val errorType  = "insufficient_scope"
}
