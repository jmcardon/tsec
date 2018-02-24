package tsec.passwordhashers.core

import java.nio.CharBuffer

import cats.Id
import cats.effect.Sync
import tsec.common._

trait PasswordHashAPI[A] {

  def hashpwUnsafe(p: String)(implicit P: PasswordHasher[Id, A]): PasswordHash[A] = hashpwUnsafe(p.asciiBytes)

  /** Hash a password in a char array
    * then clear the data in the password original
    * array, as well as the byte encoding change.
    *
    * @param p the encoded password
    * @return
    */
  def hashpwUnsafe(p: Array[Char])(implicit P: PasswordHasher[Id, A]): PasswordHash[A] = {
    val charbuffer = CharBuffer.wrap(p)
    val bytes      = defaultCharset.encode(charbuffer).array()
    val out        = P.hashpw(bytes)
    //Clear pass
    ByteUtils.zeroCharArray(p)
    ByteUtils.zeroByteArray(bytes)
    PasswordHash[A](out)
  }

  /** Hash a password in utf-8 encoded bytes,
    * then clear the data in the password
    *
    * @param p the encoded password
    * @return
    */
  def hashpwUnsafe(p: Array[Byte])(implicit P: PasswordHasher[Id, A]): PasswordHash[A] = {
    val out = PasswordHash[A](P.hashpw(p))
    ByteUtils.zeroByteArray(p)
    out
  }

  def hashpw[F[_]](p: String)(implicit P: PasswordHasher[F, A]): F[PasswordHash[A]] = hashpw[F](p.asciiBytes)

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

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: String, hash: PasswordHash[A])(implicit P: PasswordHasher[Id, A]): Boolean =
    checkpwUnsafe(p.asciiBytes, hash)

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: Array[Byte], hash: PasswordHash[A])(implicit P: PasswordHasher[Id, A]): Boolean = {
    val out = P.checkpw(p, hash)
    //Clear pass
    ByteUtils.zeroByteArray(p)
    out
  }

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: Array[Char], hash: PasswordHash[A])(implicit P: PasswordHasher[Id, A]): Boolean = {
    val charbuffer = CharBuffer.wrap(p)
    val bytes      = defaultCharset.encode(charbuffer).array()
    val out        = P.checkpw(bytes, hash)
    //Clear pass
    ByteUtils.zeroCharArray(p)
    ByteUtils.zeroByteArray(bytes)
    out
  }

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw[F[_]: Sync](p: String, hash: PasswordHash[A])(implicit P: PasswordHasher[F, A]): F[Boolean] =
    checkpw[F](p.asciiBytes, hash)

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

}
