package tsec.authentication.credentials

import cats.effect.Sync
import cats.syntax.all._
import tsec.passwordhashers._
import tsec.passwordhashers.core.{PWHashPrograms, PasswordValidated}
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

abstract class PasswordStore[F[_]: Sync, Id, P](implicit h: PWHashPrograms[PasswordValidated, P]) extends CredentialStore[F, RawCredentials[Id], P] {

  def retrievePass(id: Id): F[P]

  def authenticate(credentials: RawCredentials[Id]): F[Boolean] =
    retrievePass(credentials.identity).map(credentials.rawPassword.checkWithHash[P])
}

trait SCryptPasswordStore[F[_], Id] extends PasswordStore[F, Id, SCrypt]

trait BCryptPasswordStore[F[_], Id] extends PasswordStore[F, Id, BCrypt]