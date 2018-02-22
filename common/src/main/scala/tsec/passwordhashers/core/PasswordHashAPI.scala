package tsec.passwordhashers.core

import java.nio.CharBuffer
import cats.effect.Sync
import tsec.common._

trait PasswordHashAPI[A, S] {

  def hashpwUnsafe(p: String)(implicit S: S): PasswordHash[A] = hashpwUnsafe(p.utf8Bytes)

  /** Hash a password in a char array
    * then clear the data in the password original
    * array, as well as the byte encoding change.
    *
    * @param p the encoded password
    * @return
    */
  def hashpwUnsafe(p: Array[Char])(implicit S: S): PasswordHash[A] = {
    val charbuffer = CharBuffer.wrap(p)
    val bytes      = defaultCharset.encode(charbuffer).array()
    val out        = hashPassUnsafe(bytes)
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
  def hashpwUnsafe(p: Array[Byte])(implicit S: S): PasswordHash[A] = {
    val out = PasswordHash[A](hashPassUnsafe(p))
    ByteUtils.zeroByteArray(p)
    out
  }

  def hashpw[F[_]](p: String)(implicit F: Sync[F], S: S): F[PasswordHash[A]] = hashpw[F](p.utf8Bytes)

  /** Hash a password in a char array
    * then clear the data in the password original
    * array, as well as the byte encoding change,
    * but in a pure fashion because
    * side effects suck butt.
    *
    */
  def hashpw[F[_]](p: Array[Char])(implicit F: Sync[F], S: S): F[PasswordHash[A]] = F.delay(hashpwUnsafe(p))

  /** Hash a password in utf-8 encoded bytes,
    * then clear the data in the password,
    * but in a pure way.
    *
    * @param p the encoded password
    * @return
    */
  def hashpw[F[_]](p: Array[Byte])(implicit F: Sync[F], S: S): F[PasswordHash[A]] = F.delay(hashpwUnsafe(p))

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: String, hash: PasswordHash[A])(implicit S: S): Boolean = checkpwUnsafe(p.utf8Bytes, hash)

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  def checkpwUnsafe(p: Array[Byte], hash: PasswordHash[A])(implicit S: S): Boolean = {
    val out = checkPassUnsafe(p, hash)
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
  def checkpwUnsafe(p: Array[Char], hash: PasswordHash[A])(implicit S: S): Boolean = {
    val charbuffer = CharBuffer.wrap(p)
    val bytes      = defaultCharset.encode(charbuffer).array()
    val out        = checkPassUnsafe(bytes, hash)
    //Clear pass
    ByteUtils.zeroCharArray(p)
    ByteUtils.zeroByteArray(bytes)
    out
  }

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw[F[_]: Sync](p: String, hash: PasswordHash[A])(implicit S: S): F[Boolean] =
    checkpw[F](p.utf8Bytes, hash)

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw[F[_]](p: Array[Char], hash: PasswordHash[A])(implicit F: Sync[F], S: S): F[Boolean] =
    F.delay(checkpwUnsafe(p, hash))

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw[F[_]](p: Array[Byte], hash: PasswordHash[A])(implicit F: Sync[F], S: S): F[Boolean] =
    F.delay(checkpwUnsafe(p, hash))

  /** Internal api **/
  private[tsec] def hashPassUnsafe(p: Array[Byte])(implicit S: S): String

  private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[A])(implicit S: S): Boolean
}
