package tsec.authentication

import tsec.cipher.symmetric.imports._

class EncryptedCookieAuthenticatorTests extends EncryptedCookieAuthenticatorSpec {

  AuthenticatorTest[AES128]("AES128 Authenticator w\\ backing store", genStatefulAuthenticator[AES128])
  AuthenticatorTest[AES192]("AES192 Authenticator w\\ backing store", genStatefulAuthenticator[AES192])
  AuthenticatorTest[AES256]("AES256 Authenticator w\\ backing store", genStatefulAuthenticator[AES256])
  AuthenticatorTest[AES128]("AES128 Authenticator stateless", genStatelessAuthenticator[AES128])
  AuthenticatorTest[AES192]("AES192 Authenticator stateless", genStatelessAuthenticator[AES192])
  AuthenticatorTest[AES256]("AES256 Authenticator stateless", genStatelessAuthenticator[AES256])

  RequestAuthTests[AES128]("AES128 Authenticator w\\ backing store", genStatefulAuthenticator[AES128])
  RequestAuthTests[AES192]("AES192 Authenticator w\\ backing store", genStatefulAuthenticator[AES192])
  RequestAuthTests[AES256]("AES256 Authenticator w\\ backing store", genStatefulAuthenticator[AES256])
  RequestAuthTests[AES128]("AES128 Authenticator stateless", genStatelessAuthenticator[AES128])
  RequestAuthTests[AES192]("AES192 Authenticator stateless", genStatelessAuthenticator[AES192])
  RequestAuthTests[AES256]("AES256 Authenticator stateless", genStatelessAuthenticator[AES256])
}
