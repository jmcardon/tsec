package tsec.authentication.credentials

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.all._
import tsec.passwordhashers._
import tsec.passwordhashers.jca._

/** An trait representing the common operations you would do to/with credentials, such as
  * logging in with a password, or validating an oauth token to log in
  *
  */
trait CredentialStore[F[_], C, P] {

  /** Add credentials to some backing store.
    * `putCredentials` takes a function, most likely
    * partially applied on some userId, that takes a `P`
    * and adds some user record onto a credentials store.
    *
    * @param credentials
    * @param put
    * @return
    */
  def putCredentials(credentials: C, put: P => F[Unit]): F[Unit]

  /** Alias for `putCredentials`
    * for when anyone may want to be verbose about
    * put vs update
    */
  def updateCredentials(credentials: C, update: P => F[Unit]): F[Unit] =
    putCredentials(credentials, update)

  @deprecated("Use isAuthenticated", "0.0.1-M10")
  def authenticate(credentials: C): F[Boolean]

  def isAuthenticated(credentials: C): F[Boolean]
}

abstract class PasswordStore[F[_], Id, P](implicit P: PasswordHasher[F, P], F: Sync[F])
    extends CredentialStore[F, RawCredentials[Id], PasswordHash[P]] {

  def retrievePass(id: Id): OptionT[F, PasswordHash[P]]

  @deprecated("Use isAuthenticated", "0.0.1-M10")
  def authenticate(credentials: RawCredentials[Id]): F[Boolean] =
    isAuthenticated(credentials)

  def putCredentials(credentials: RawCredentials[Id], put: PasswordHash[P] => F[Unit]): F[Unit] =
    for {
      hash <- P.hashpw(credentials.rawPassword)
      _    <- put(hash)
    } yield ()

  def putCredentials(raw: Array[Byte], put: PasswordHash[P] => F[Unit]): F[Unit] =
    for {
      hash <- P.hashpw(raw)
      _    <- put(hash)
    } yield ()

  def putCredentials(raw: Array[Char], put: PasswordHash[P] => F[Unit]): F[Unit] =
    for {
      hash <- P.hashpw(raw)
      _    <- put(hash)
    } yield ()

  def isAuthenticated(credentials: RawCredentials[Id]): F[Boolean] =
    for {
      pass <- retrievePass(credentials.identity)
        .getOrElseF(F.raiseError(CredentialsError("No such user")))
      check <- P.checkpwBool(credentials.rawPassword, pass)
    } yield check

  def isAuthenticated(id: Id, raw: Array[Byte]): F[Boolean] =
    for {
      pass <- retrievePass(id)
        .getOrElseF(F.raiseError(CredentialsError("No such user")))
      check <- P.checkpwBool(raw, pass)
    } yield check

  def isAuthenticated(id: Id, raw: Array[Char]): F[Boolean] =
    for {
      pass <- retrievePass(id)
        .getOrElseF(F.raiseError(CredentialsError("No such user")))
      check <- P.checkpwBool(raw, pass)
    } yield check
}

trait SCryptPasswordStore[F[_], Id] extends PasswordStore[F, Id, SCrypt]

trait BCryptPasswordStore[F[_], Id] extends PasswordStore[F, Id, BCrypt]
