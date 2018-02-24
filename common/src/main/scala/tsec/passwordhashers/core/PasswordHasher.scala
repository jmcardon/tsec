package tsec.passwordhashers.core

import java.nio.CharBuffer

import cats.Id
import tsec.common._

//Todo: deal with unsafe pw hashing in a more principled style
trait PasswordHasher[F[_], A] {

  final def hashpwUnsafe(p: String): PasswordHash[A] = hashpwUnsafe(p.asciiBytes)

  /** Hash a password in a char array
    * then clear the data in the password original
    * array, as well as the byte encoding change.
    *
    * @param p the encoded password
    * @return
    */
  final def hashpwUnsafe(p: Array[Char]): PasswordHash[A] = {
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
  final def hashpwUnsafe(p: Array[Byte]): PasswordHash[A] = {
    val out = PasswordHash[A](hashPassUnsafe(p))
    ByteUtils.zeroByteArray(p)
    out
  }

  final def hashpw(p: String): F[PasswordHash[A]] = hashpw(p.asciiBytes)

  /** Hash a password in a char array
    * then clear the data in the password original
    * array, as well as the byte encoding change,
    * but in a pure fashion because
    * side effects suck butt.
    *
    */
  def hashpw(p: Array[Char]): F[PasswordHash[A]]

  /** Hash a password in utf-8 encoded bytes,
    * then clear the data in the password,
    * but in a pure way.
    *
    * @param p the encoded password
    * @return
    */
  def hashpw(p: Array[Byte]): F[PasswordHash[A]]

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  final def checkpwUnsafe(p: String, hash: PasswordHash[A]): Boolean = checkpwUnsafe(p.asciiBytes, hash)

  /** Check against a bcrypt hash in an unsafe
    * manner.
    *
    * It may throw an exception for a malformed password
    * @return
    */
  final def checkpwUnsafe(p: Array[Byte], hash: PasswordHash[A]): Boolean = {
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
  final def checkpwUnsafe(p: Array[Char], hash: PasswordHash[A]): Boolean = {
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
  final def checkpw(p: String, hash: PasswordHash[A]): F[Boolean] = checkpw(p.asciiBytes, hash)

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw(p: Array[Char], hash: PasswordHash[A]): F[Boolean]

  /** Check against a bcrypt hash in a pure way
    *
    * It may raise an error for a malformed hash
    */
  def checkpw(p: Array[Byte], hash: PasswordHash[A]): F[Boolean]

  /** Internal api **/
  private[tsec] def hashPassUnsafe(p: Array[Byte]): String

  private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[A]): Boolean

}

trait IdPasswordHasher[A] extends PasswordHasher[Id, A] {
  def hashpw(p: Array[Char]): Id[PasswordHash[A]] = hashpwUnsafe(p)

  def hashpw(p: Array[Byte]): Id[PasswordHash[A]] = hashpwUnsafe(p)

  def checkpw(p: Array[Char], hash: PasswordHash[A]): Id[Boolean] = checkpwUnsafe(p, hash)

  def checkpw(p: Array[Byte], hash: PasswordHash[A]): Id[Boolean] = checkpwUnsafe(p, hash)
}
