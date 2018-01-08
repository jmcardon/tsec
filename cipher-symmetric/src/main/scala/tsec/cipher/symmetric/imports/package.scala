package tsec.cipher.symmetric

import javax.crypto.spec.{GCMParameterSpec, IvParameterSpec}
import javax.crypto.{Cipher => JCipher, SecretKey => JSecretKey}

import cats.evidence.Is
import tsec.cipher.common.padding.{NoPadding, PKCS7Padding, SymmetricPadding}
import tsec.cipher.symmetric.core.{Iv, IvStrategy}
import tsec.cipher.symmetric.imports.primitive.{JCAAEADPrimitive, JCAPrimitiveCipher}
import tsec.common.{JKeyGenerator, ManagedRandom}

package object imports {

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

  /** Our typeclass generalizing over AES,
    * that lends itself to variable key sizes
    * (128, 192 and 256 bits).
    *
    */
  trait AES[A] extends BlockCipher[A] with AEADCipher[A] {
    val cipherName: String  = "AES"
    val blockSizeBytes: Int = 16
    val tagSizeBytes: Int   = GCM.NISTTagLengthBits / 8
  }

  /**
    * This trait propagates type information
    * about a parametrized M being a symmetric cipher mode of operation
    * @tparam M
    */
  trait CipherMode[M] {
    def mode: String
  }

  private[tsec] trait TaggedSecretKey {
    type KeyRepr[A]
    def is[A]: Is[KeyRepr[A], JSecretKey]
  }

  protected val SecretKey$$ : TaggedSecretKey = new TaggedSecretKey {
    type KeyRepr[A] = JSecretKey
    @inline def is[A]: Is[KeyRepr[A], JSecretKey] = Is.refl[JSecretKey]
  }

  type SecretKey[A] = SecretKey$$.KeyRepr[A]

  object SecretKey {
    @inline def apply[A: Cipher](key: JSecretKey): SecretKey[A]     = SecretKey$$.is.flip.coerce(key)
    @inline def toJavaKey[A: Cipher](key: SecretKey[A]): JSecretKey = SecretKey$$.is.coerce(key)
    @inline def is[A]: Is[SecretKey[A], JSecretKey]                 = SecretKey$$.is[A]
  }

  final class SecretKeySyntax[A](val key: SecretKey[A]) extends AnyVal {
    @inline def toJavaKey: JSecretKey = SecretKey$$.is.coerce(key)
    def getEncoded: Array[Byte]       = SecretKey$$.is.coerce(key).getEncoded
  }

  implicit final def _secretKeySyntax[A](key: SecretKey[A]) = new SecretKeySyntax[A](key)

  trait CipherKeyGen[A] extends JKeyGenerator[A, SecretKey, CipherKeyBuildError]

  class WithCipherMode[M](val mode: String) extends CipherMode[M] {
    implicit val m: CipherMode[M] = this
  }

  private[tsec] def standardProcess[A, M, P: SymmetricPadding](
      implicit cipher: BlockCipher[A]
  ): IvProcess[A, M, P, SecretKey] =
    new IvProcess[A, M, P, SecretKey] {

      val ivLengthBytes: Int = cipher.blockSizeBytes

      private[tsec] def encryptInit(cipher: JCipher, iv: Iv[A, M], key: SecretKey[A]): Unit =
        cipher.init(
          JCipher.ENCRYPT_MODE,
          key.toJavaKey,
          new IvParameterSpec(iv)
        )

      private[tsec] def decryptInit(cipher: JCipher, iv: Iv[A, M], key: SecretKey[A]): Unit =
        cipher.init(
          JCipher.DECRYPT_MODE,
          key.toJavaKey,
          new IvParameterSpec(iv)
        )
    }

  /*
  Modes of operation
   */
  sealed trait CBC

  object CBC extends WithCipherMode[CBC]("CBC") {
    implicit def cbcProcess[A, P: SymmetricPadding](implicit cipher: BlockCipher[A]): IvProcess[A, CBC, P, SecretKey] =
      standardProcess[A, CBC, P]
  }

  sealed trait CFB

  object CFB extends WithCipherMode[CFB]("CFB") {
    implicit def cfbProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, CFB, NoPadding, SecretKey] =
      standardProcess[A, CFB, NoPadding]
  }

  sealed trait CFBx

  object CFBx extends WithCipherMode[CFBx]("CFBx") {
    implicit def cfbxProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, CFBx, NoPadding, SecretKey] =
      standardProcess[A, CFBx, NoPadding]
  }

  sealed trait CTR

  object CTR extends WithCipherMode[CTR]("CTR") {
    implicit def ctrProcess[A, P: SymmetricPadding](
        implicit cipher: BlockCipher[A]
    ): IvProcess[A, CTR, P, SecretKey] =
      standardProcess[A, CTR, P]
  }

  sealed trait ECB

  object ECB extends WithCipherMode[ECB]("ECB") {
    implicit def ecbProcess[A: BlockCipher]: IvProcess[A, ECB, NoPadding, SecretKey] =
      new IvProcess[A, ECB, NoPadding, SecretKey] {

        val ivLengthBytes: Int = 0

        private[tsec] def encryptInit(cipher: JCipher, iv: Iv[A, ECB], key: SecretKey[A]): Unit =
          cipher.init(JCipher.ENCRYPT_MODE, key.toJavaKey)

        private[tsec] def decryptInit(cipher: JCipher, iv: Iv[A, ECB], key: SecretKey[A]): Unit =
          cipher.init(JCipher.DECRYPT_MODE, key.toJavaKey)
      }
  }

  sealed trait GCM

  object GCM extends WithCipherMode[GCM]("GCM") {

    /** In our implementation, we will use the most secure tag size as defined
      * by: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
      *  Iv length of 96 bits is recommended as per the spec on page 8
      */
    val NISTTagLengthBits = 128
    val NISTIvLengthBytes = 12

    implicit def gcmProcess[A](implicit aes: AES[A]): IvProcess[A, GCM, NoPadding, SecretKey] =
      new IvProcess[A, GCM, NoPadding, SecretKey] {

        val ivLengthBytes: Int = NISTIvLengthBytes

        private[tsec] def encryptInit(cipher: JCipher, iv: Iv[A, GCM], key: SecretKey[A]): Unit =
          cipher.init(
            JCipher.ENCRYPT_MODE,
            key.toJavaKey,
            new GCMParameterSpec(GCM.NISTTagLengthBits, iv)
          )

        private[tsec] def decryptInit(cipher: JCipher, iv: Iv[A, GCM], key: SecretKey[A]): Unit =
          cipher.init(
            JCipher.DECRYPT_MODE,
            key.toJavaKey,
            new GCMParameterSpec(GCM.NISTTagLengthBits, iv)
          )
      }

    def randomIVStrategy[A: AES]: GCMIVStrategy[A] =
      new IvStrategy[A, GCM] with ManagedRandom {
        def genIvUnsafe(ptSizeBytes: Int): Iv[A, GCM] = {
          val nonce = new Array[Byte](GCM.NISTIvLengthBytes)
          nextBytes(nonce)
          Iv[A, GCM](nonce)
        }
      }

  }

  sealed trait NoMode

  object NoMode extends WithCipherMode[NoMode]("NoMode") {
    implicit def noModeProcess[A: BlockCipher]: IvProcess[A, NoMode, NoPadding, SecretKey] =
      new IvProcess[A, NoMode, NoPadding, SecretKey] {

        val ivLengthBytes: Int = 0

        private[tsec] def encryptInit(cipher: JCipher, iv: Iv[A, NoMode], key: SecretKey[A]): Unit =
          cipher.init(JCipher.ENCRYPT_MODE, key.toJavaKey)

        private[tsec] def decryptInit(cipher: JCipher, iv: Iv[A, NoMode], key: SecretKey[A]): Unit =
          cipher.init(JCipher.DECRYPT_MODE, key.toJavaKey)
      }
  }

  sealed trait OFB

  object OFB extends WithCipherMode[OFB]("OFB") {
    implicit def ofbProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, OFB, NoPadding, SecretKey] =
      standardProcess[A, OFB, NoPadding]
  }

  sealed trait OFBx

  object OFBx extends WithCipherMode[OFBx]("OFBx") {
    implicit def ofbxProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, OFBx, NoPadding, SecretKey] =
      standardProcess[A, OFBx, NoPadding]
  }

  sealed trait PCBC

  object PCBC extends WithCipherMode[PCBC]("PCBC") {
    implicit def pcbcProcess[A, P: SymmetricPadding](
        implicit cipher: BlockCipher[A]
    ): IvProcess[A, PCBC, P, SecretKey] =
      standardProcess[A, PCBC, P]
  }

  /** Type aliases for default constructions **/
  type GCMCipherText[A] = CipherText[A, GCM, NoPadding]

  type GCMEncryptor[F[_], A] = JCAAEADPrimitive[F, A, GCM, NoPadding]

  type GCMIVStrategy[A] = IvStrategy[A, GCM]

  /** CBC aliases **/
  type CBCCipherText[A] = CipherText[A, CBC, PKCS7Padding]

  type CBCEncryptor[F[_], C] = JCAPrimitiveCipher[F, C, CBC, PKCS7Padding]

  type CBCIVStrategy[A] = IvStrategy[A, CBC]

  /** CTR aliases **/
  type CTRCipherText[A] = CipherText[A, CTR, NoPadding]

  type CTREncryptor[F[_], C] = JCAPrimitiveCipher[F, C, CTR, NoPadding]

  type CTRIVStrategy[A] = IvStrategy[A, CTR]

}
