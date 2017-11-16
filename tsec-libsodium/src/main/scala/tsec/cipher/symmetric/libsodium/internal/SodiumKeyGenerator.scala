package tsec.cipher.symmetric.libsodium.internal

import cats.effect.Sync
import tsec.ScalaSodium

/** Our symmetric key generator, abstracted out
  * This is not so easy given keyError is useful to CipherError as well, but
  * duplicated classes is a nono
  *
  * @tparam A The algorithm to generate the key for
  * @tparam K the key type, i.e Symmetric cipher or Mac key
  */
protected[tsec] trait SodiumKeyGenerator[A, K[_]] {

  /** The generator key length
    * @return
    */
  val keyLength: Int

  /** Generate a Key, or return a key error for a missing provider
    * @return Either the Key, or an error
    */
  def generateKey[F[_]](implicit F: Sync[F], s: ScalaSodium): F[K[A]]

  /** Generate key, but with errors uncaught
    * This does not shield you from JCA exceptions
    *
    * @return
    */
  def generateKeyUnsafe(implicit s: ScalaSodium): K[A]

  /** Build a key for the particular cipher from the provided bytes,
    * based on the key length
    *
    * @param key
    * @return
    */
  def buildKey[F[_]](key: Array[Byte])(implicit F: Sync[F], s: ScalaSodium): F[K[A]]

  /** Same as prior, except yolo out the exceptions.
    *
    * @param key
    * @return
    */
  def buildKeyUnsafe(key: Array[Byte])(implicit s: ScalaSodium): K[A]
}
