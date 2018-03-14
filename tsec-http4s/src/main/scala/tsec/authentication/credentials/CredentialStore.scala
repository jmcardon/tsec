package tsec.authentication.credentials

import cats.effect.Sync
import cats.syntax.all._
import tsec.passwordhashers._
import tsec.passwordhashers.imports._

/** An trait representing the common operations you would do to/with credentials, such as
  * logging in with a password, or validating an oauth token to log in
  *
  */
trait CredentialStore[F[_], C, P] {

  def putCredentials(credentials: C): F[Unit]

  def updateCredentials(credentials: C): F[Unit]

  def removeCredentials(credentials: C): F[Unit]

  def authenticate(credentials: C): F[Boolean]
}

abstract class PasswordStore[F[_]: Sync, Id, P](implicit h: PasswordHasher[F, P])
    extends CredentialStore[F, RawCredentials[Id], P] {

  def retrievePass(id: Id): F[PasswordHash[P]]

  def authenticate(credentials: RawCredentials[Id]): F[Boolean] =
    for {
      pass  <- retrievePass(credentials.identity)
      check <- h.checkpw(credentials.rawPassword, pass)
    } yield check
}

trait SCryptPasswordStore[F[_], Id] extends PasswordStore[F, Id, SCrypt]

trait BCryptPasswordStore[F[_], Id] extends PasswordStore[F, Id, BCrypt]
