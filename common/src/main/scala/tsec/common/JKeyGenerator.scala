package tsec.common

import javax.crypto.KeyGenerator

import cats.effect.Sync
import cats.syntax.either._

/** Our symmetric key generator, abstracted out
  * This is not so easy given keyError is useful to CipherError as well, but
  * duplicated classes is a nono
  *
  * @tparam A The algorithm to generate the key for
  * @tparam K the key type, i.e Symmetric cipher or Mac key
  * @tparam KE the key error type
  */
@deprecated("Use SymmetricKeyGen", "0.0.1-M10")
protected[tsec] trait JKeyGenerator[A, K[_], KE] {

  /** The generator to return
    * @return
    */
  def generator: KeyGenerator

  /** Generate a Key, or return a key error for a missing provider
    * Todo: Rename, in terms of unsafe
    * @return Either the Key, or an error
    */
  def generateKey(): Either[KE, K[A]]

  /** Lift our generation code into an F[_]
    * Todo: Rename
    *
    * @param F Sync instance
    * @tparam F
    * @return
    */
  def generateLift[F[_]](implicit F: Sync[F]): F[K[A]] =
    F.delay(generateKeyUnsafe())

  /** Generate key, but with errors uncaught
    * This does not shield you from JCA exceptions
    *
    * @return
    */
  def generateKeyUnsafe(): K[A]

  /** Build a key for the particular cipher from the provided bytes,
    * based on the key length
    * Todo: In terms of unsafe
    *
    * @param key
    * @return
    */
  def buildKey(key: Array[Byte]): Either[KE, K[A]]

  /** Build a key, lift onto a context F[_]
    *
    * @param rawKey
    * @param F
    * @param ev
    * @tparam F
    * @return
    */
  def buildAndLift[F[_]](rawKey: Array[Byte])(implicit F: Sync[F], ev: KE <:< Throwable): F[K[A]] =
    F.fromEither(buildKey(rawKey).leftMap(ev(_)))

  /** Same as prior, except yolo out the exceptions.
    *
    * @param key
    * @return
    */
  def buildKeyUnsafe(key: Array[Byte]): K[A]
}
