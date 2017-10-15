package tsec.common

import javax.crypto.KeyGenerator

import cats.ApplicativeError

/** Our symmetric key generator, abstracted out
  * This is not so easy given keyError is useful to CipherError as well, but
  * duplicated classes is a nono
  *
  * @tparam A The algorithm to generate the key for
  * @tparam K the key type, i.e Symmetric cipher or Mac key
  * @tparam KE the key error type
  */
protected[tsec] trait JKeyGenerator[A, K[_], KE] {

  /** The generator key length
    * @return
    */
  def keyLength: Int

  /** The generator to return
    * @return
    */
  def generator: KeyGenerator

  /** Generate a Key, or return a key error for a missing provider
    * @return Either the Key, or an error
    */
  def generateKey(): Either[KE, K[A]]

  /** Lift our generation code into an F[_]
    *
    * @param err ApplicativeError instance
    * @tparam F
    * @return
    */
  def generateLift[F[_]](implicit err: ApplicativeError[F, Throwable]): F[K[A]] =
    err.catchNonFatal(generateKeyUnsafe())

  /** Generate key, but with errors uncaught
    * This does not shield you from JCA exceptions
    *
    * @return
    */
  def generateKeyUnsafe(): K[A]

  /** Build a key for the particular cipher from the provided bytes,
    * based on the key length
    *
    * @param key
    * @return
    */
  def buildKey(key: Array[Byte]): Either[KE, K[A]]

  /** Same as prior, except yolo out the exceptions.
    *
    * @param key
    * @return
    */
  def buildKeyUnsafe(key: Array[Byte]): K[A]
}
