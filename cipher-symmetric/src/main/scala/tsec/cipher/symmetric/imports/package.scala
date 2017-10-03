package tsec.cipher.symmetric

import tsec.cipher.common._
import tsec.cipher.common.mode.GCM
import tsec.cipher.common.padding.NoPadding
import tsec.common.{CryptoTag, JKeyGenerator}
import javax.crypto.{SecretKey => JSecretKey}

import cats.evidence.Is

package object imports{
  type AEADCipherText[A] = CipherText[A, GCM, NoPadding]

  /**
   * Typeclass for propagating symmetric key algorithm information
   * Note: Key length is in bits
   *
   * @param algorithm the symmetric cipher representation, as a string
   * @param keyLength key length in bits
   * @tparam T Parametrized cipher type
   */
  protected[tsec] case class SymmetricAlgorithm[T](algorithm: String, keyLength: Int) extends CryptoTag[T]

  sealed trait TaggedSecretKey {
    type KeyRepr
    val is: Is[KeyRepr, JSecretKey]
  }

  val SecretKey$$: TaggedSecretKey = new TaggedSecretKey {
    type KeyRepr = JSecretKey
    val is = Is.refl[JSecretKey]
  }

  type SecretKey[A] = SecretKey$$.KeyRepr

  object SecretKey {
    @inline def apply[A: SymmetricAlgorithm](key: JSecretKey): SecretKey[A] = SecretKey$$.is.flip.coerce(key)
    @inline def toJavaKey[A: SymmetricAlgorithm](key: SecretKey[A]): JSecretKey = SecretKey$$.is.coerce(key)
  }

  trait CipherKeyGen[A] extends JKeyGenerator[A, SecretKey, CipherKeyBuildError]
}
