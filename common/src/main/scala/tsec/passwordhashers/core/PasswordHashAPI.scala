package tsec.passwordhashers.core

import cats.Id
import cats.effect.Sync

trait PasswordHashAPI[A] {

  def hashpw[F[_]](p: String)(implicit P: PasswordHasher[F, A]): F[PasswordHash[A]] =
    P.hashpw(p)

  /** Hash a password in a char array
    * then clear the data in the password original
    * array, as well as the byte encoding change,
    * but in a pure fashion because
    * side effects suck butt.
    *
    */
  def hashpw[F[_]](p: Array[Char])(implicit P: PasswordHasher[F, A]): F[PasswordHash[A]] = P.hashpw(p)

  /** Hash a password in utf-8 encoded bytes,
    * then clear the data in the password,
    * but in a pure way.
    *
    * @param p the encoded password
    * @return
    */
  def hashpw[F[_]](p: Array[Byte])(implicit P: PasswordHasher[F, A]): F[PasswordHash[A]] =
    P.hashpw(p)

  def hashpwUnsafe(p: String)(implicit P: PasswordHasher[Id, A]): PasswordHash[A] =
    P.hashpwUnsafe(p)

  /** Hash a password in a char array
    * then clear the data in the password original
    * array, as well as the byte encoding change.
    *
    * @param p the encoded password
    * @return
    */
  def hashpwUnsafe(p: Array[Char])(implicit P: PasswordHasher[Id, A]): PasswordHash[A] =
    P.hashpwUnsafe(p)

  /** Hash a password in utf-8 encoded bytes,
    * then clear the data in the password
    *
    * @param p the encoded password
    * @return
    */
  def hashpwUnsafe(p: Array[Byte])(implicit P: PasswordHasher[Id, A]): PasswordHash[A] =
    P.hashpwUnsafe(p)

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw[F[_]: Sync](p: String, hash: PasswordHash[A])(implicit P: PasswordHasher[F, A]): F[Boolean] =
    P.checkpw(p, hash)

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw[F[_]](p: Array[Char], hash: PasswordHash[A])(implicit P: PasswordHasher[F, A]): F[Boolean] =
    P.checkpw(p, hash)

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw[F[_]](p: Array[Byte], hash: PasswordHash[A])(implicit F: Sync[F], P: PasswordHasher[F, A]): F[Boolean] =
    P.checkpw(p, hash)

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: String, hash: PasswordHash[A])(implicit P: PasswordHasher[Id, A]): Boolean =
    P.checkpwUnsafe(p, hash)

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: Array[Byte], hash: PasswordHash[A])(implicit P: PasswordHasher[Id, A]): Boolean =
    P.checkpwUnsafe(p, hash)

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: Array[Char], hash: PasswordHash[A])(implicit P: PasswordHasher[Id, A]): Boolean =
    P.checkpwUnsafe(p, hash)

}
