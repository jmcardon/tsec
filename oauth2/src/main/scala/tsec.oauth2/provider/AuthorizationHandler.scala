package tsec.oauth2.provider

/**
  * Provide <b>Authorization</b> phases support for using OAuth 2.0.
  *
  * <h3>[Authorization phases]</h3>
  *
  * <h4>Authorization Code Grant</h4>
  * <ul>
  *   <li>validateClient(request)</li>
  *   <li>findAuthInfoByCode(code)</li>
  *   <li>deleteAuthCode(code)</li>
  *   <li>getStoredAccessToken(authInfo)</li>
  *   <li>refreshAccessToken(authInfo, token)</li>
  *   <li>createAccessToken(authInfo)</li>
  * </ul>
  *
  * <h4>Refresh Token Grant</h4>
  * <ul>
  *   <li>validateClient(clientCredential, grantType)</li>
  *   <li>findAuthInfoByRefreshToken(refreshToken)</li>
  *   <li>refreshAccessToken(authInfo, refreshToken)</li>
  * </ul>
  *
  * <h4>Resource Owner Password Credentials Grant</h4>
  * <ul>
  *   <li>validateClient(request)</li>
  *   <li>findUser(request)</li>
  *   <li>getStoredAccessToken(authInfo)</li>
  *   <li>refreshAccessToken(authInfo, token)</li>
  *   <li>createAccessToken(authInfo)</li>
  * </ul>
  *
  * <h4>Client Credentials Grant</h4>
  * <ul>
  *   <li>validateClient(request)</li>
  *   <li>findUser(request)</li>
  *   <li>getStoredAccessToken(authInfo)</li>
  *   <li>refreshAccessToken(authInfo, token)</li>
  *   <li>createAccessToken(authInfo)</li>
  * </ul>
  *
  * <h4>Implicit Grant</h4>
  * <ul>
  *   <li>validateClient(request)</li>
  *   <li>findUser(request)</li>
  *   <li>getStoredAccessToken(authInfo)</li>
  *   <li>createAccessToken(authInfo)</li>
  * </ul>
  *
  */
trait AuthorizationHandler[F[_], U] {

  /**
    * Verify proper client with parameters for issue an access token.
    * Note that per the OAuth Specification, a Client may be valid if it only contains a client ID but no client
    * secret (common with Public Clients). However, if the registered client has a client secret value the specification
    * requires that a client secret must always be provided and verified for that client ID.
    *
    * @param credential client credential parsed from request
    * @param request Request sent by client.
    * @return true if request is a regular client, false if request is a illegal client.
    */
  def validateClient(credential: ClientCredential, request: ValidatedRequest): F[Boolean]

  /**
    * Authenticate the user that issued the authorization request.
    * Client credential, Password and Implicit Grant call this method.
    *
    * @param maybeCredential client credential parsed from request
    * @param request Request sent by client.
    */
  def findUser(maybeCredential: Option[ClientCredential], request: ValidatedRequest): F[Option[U]]

  /**
    * Creates a new access token by authorized information.
    *
    * @param authInfo This value is already authorized by system.
    * @return Access token returns to client.
    */
  def createAccessToken(authInfo: AuthInfo[U]): F[AccessToken]

  /**
    * Returns stored access token by authorized information.
    *
    * If want to create new access token then have to return None
    *
    * @param authInfo This value is already authorized by system.
    * @return Access token returns to client.
    */
  def getStoredAccessToken(authInfo: AuthInfo[U]): F[Option[AccessToken]]

  /**
    * Creates a new access token by refreshToken.
    *
    * @param authInfo This value is already authorized by system.
    * @return Access token returns to client.
    */
  def refreshAccessToken(authInfo: AuthInfo[U], refreshToken: String): F[AccessToken]

  /**
    * Find authorized information by authorization code.
    *
    * If you don't support Authorization Code Grant then doesn't need implementing.
    *
    * @param code Client sends authorization code which is registered by system.
    * @return Return authorized information that matched the code.
    */
  def findAuthInfoByCode(code: String): F[Option[AuthInfo[U]]]

  /**
    * Deletes an authorization code.
    *
    * Called when an AccessToken has been successfully issued via an authorization code.
    *
    * If you don't support Authorization Code Grant, then you don't need to implement this
    * method.
    *
    * @param code Client-sent authorization code
    */
  def deleteAuthCode(code: String): F[Unit]

  /**
    * Find authorized information by refresh token.
    *
    * If you don't support Refresh Token Grant then doesn't need implementing.
    *
    * @param refreshToken Client sends refresh token which is created by system.
    * @return Return authorized information that matched the refresh token.
    */
  def findAuthInfoByRefreshToken(refreshToken: String): F[Option[AuthInfo[U]]]

}
