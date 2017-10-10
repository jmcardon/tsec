package tsec.authentication

import java.util.UUID

import cats.effect.IO
import tsec.cipher.symmetric.imports._
import tsec.jws.mac.JWTMac
import tsec.mac.imports._

class JWTAuthenticatorTests extends JWTAuthenticatorSpec {

  AuthenticatorTest[HMACSHA256]("HMACSHA256 JWT Stateful Authenticator", genStatefulAuthenticator[HMACSHA256, AES128])
  AuthenticatorTest[HMACSHA384]("HMACSHA384 JWT Stateful Authenticator", genStatefulAuthenticator[HMACSHA384, AES128])
  AuthenticatorTest[HMACSHA512]("HMACSHA512 JWT Stateful Authenticator", genStatefulAuthenticator[HMACSHA512, AES128])
  AuthenticatorTest[HMACSHA256]("HMACSHA256 JWT Stateless Authenticator", genStateless[HMACSHA256, AES128])
  AuthenticatorTest[HMACSHA384]("HMACSHA384 JWT Stateless Authenticator", genStateless[HMACSHA384, AES128])
  AuthenticatorTest[HMACSHA512]("HMACSHA512 JWT Stateless Authenticator", genStateless[HMACSHA512, AES128])

  RequestAuthTests[HMACSHA256]("HMACSHA256 JWT Stateful Authenticator", genStatefulAuthenticator[HMACSHA256, AES128])
  RequestAuthTests[HMACSHA384]("HMACSHA384 JWT Stateful Authenticator", genStatefulAuthenticator[HMACSHA384, AES128])
  RequestAuthTests[HMACSHA512]("HMACSHA512 JWT Stateful Authenticator", genStatefulAuthenticator[HMACSHA512, AES128])
  RequestAuthTests[HMACSHA256]("HMACSHA256 JWT Stateless Authenticator", genStateless[HMACSHA256, AES128])
  RequestAuthTests[HMACSHA384]("HMACSHA384 JWT Stateless Authenticator", genStateless[HMACSHA384, AES128])
  RequestAuthTests[HMACSHA512]("HMACSHA512 JWT Stateless Authenticator", genStateless[HMACSHA512, AES128])
}
