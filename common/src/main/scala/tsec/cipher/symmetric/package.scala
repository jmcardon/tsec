package tsec.cipher

import tsec.common.{ArrayHKNewt, ArrayNewt}

package object symmetric {
  type Iv[A] = Iv.Type[A]

  object Iv extends ArrayHKNewt

  type RawCipherText[A] = RawCipherText.Type[A]

  object RawCipherText extends ArrayHKNewt

  type PlainText = PlainText.Type

  object PlainText extends ArrayNewt

  type AAD = AAD.Type

  object AAD extends ArrayNewt

  type AuthTag[A] = AuthTag.Type[A]

  object AuthTag extends ArrayHKNewt

  case class CipherText[A](content: RawCipherText[A], nonce: Iv[A]) {
    @deprecated("use toConcatenated", "0.0.1-M10")
    def toSingleArray: Array[Byte] = toConcatenated

    def toConcatenated: Array[Byte] = content ++ nonce
  }

  private[tsec] val AESBlockSize = 16

  /** Our general cipher type class,
    * to carry cipher name information,
    * block
    *
    * @tparam A
    */
  trait Cipher[A] {
    def cipherName: String
    def keySizeBytes: Int
  }

  /** Our general typeclass over block ciphers
    *
    * @tparam A
    */
  trait BlockCipher[A] extends Cipher[A] {
    def blockSizeBytes: Int
  }

  /** Typeclass evidence that some type A
    * is also an Authenticated Encryption Cipher
    *
    * It does not inherit from cipher, to
    * simply exist as an evidence typeclass
    */
  trait AECipher[A]

  /** Typeclass evidence for a construction
    * that serves as encryption for
    * Authenticated encryption with Additional Data
    *
    */
  trait AEADCipher[A] extends AECipher[A] {
    def tagSizeBytes: Int
  }

  /** In our implementation, we will use the most secure tag size as defined
    * by: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    *  Iv length of 96 bits is recommended as per the spec on page 8
    */
  val NISTTagLengthBits = 128
  val NISTIvLengthBytes = 12

  /** Our typeclass generalizing over AES,
    * that lends itself to variable key sizes
    * (128, 192 and 256 bits).
    *
    */
  trait AES[A] extends BlockCipher[A] with AEADCipher[A] {
    val cipherName: String  = "AES"
    val blockSizeBytes: Int = 16
    val tagSizeBytes: Int   = NISTTagLengthBits / 8
  }

  object AES {
    def apply[A](implicit a: AES[A]): AES[A] = a

    val AES128KeySizeBytes = 16
    val AES192KeySizeBytes = 24
    val AES256KeySizeBytes = 32
  }

  /**
    * This trait propagates type information
    * about a parametrized M being a symmetric cipher mode of operation
    * @tparam M
    */
  trait CipherMode[M] {
    def mode: String
  }

}
