package tsec.cipher

package object symmetric {
  type Iv[A] = Iv.Type[A]

  object Iv {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): Iv[A] = value.asInstanceOf[Iv[A]]
    def subst[A]: IvPartiallyApplied[A]     = new IvPartiallyApplied[A]

    private[symmetric] final class IvPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[Iv[A]] =
        value.asInstanceOf[F[Iv[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Iv[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

  type RawCipherText[A] = RawCipherText.Type[A]

  object RawCipherText {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): RawCipherText[A] = value.asInstanceOf[RawCipherText[A]]
    def subst[A]: RawCTPartiallyApplied[A]             = new RawCTPartiallyApplied[A]

    private[symmetric] final class RawCTPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[RawCipherText[A]] =
        value.asInstanceOf[F[RawCipherText[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[RawCipherText[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

  type PlainText = PlainText.Type

  object PlainText {
    type Type <: Array[Byte]

    def apply(value: Array[Byte]): PlainText             = value.asInstanceOf[PlainText]
    def subst[F[_]](value: F[Array[Byte]]): F[PlainText] = value.asInstanceOf[F[PlainText]]
  }

  type AAD = AAD.Type

  object AAD {
    type Type <: Array[Byte]

    def apply(value: Array[Byte]): AAD             = value.asInstanceOf[AAD]
    def subst[F[_]](value: F[Array[Byte]]): F[AAD] = value.asInstanceOf[F[AAD]]
  }

  type AuthTag[A] = AuthTag.Type[A]

  object AuthTag {
    type Type[A] <: Array[Byte]

    def apply[A](value: Array[Byte]): AuthTag[A] = value.asInstanceOf[AuthTag[A]]

    def subst[A]: AuthTagPartiallyApplied[A] = new AuthTagPartiallyApplied[A]

    private[symmetric] final class AuthTagPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[Array[Byte]]): F[AuthTag[A]] =
        value.asInstanceOf[F[AuthTag[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[AuthTag[A]]): F[Array[Byte]] = value.asInstanceOf[F[Array[Byte]]]
    }
  }

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
