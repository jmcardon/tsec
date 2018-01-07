package tsec.cipher.symmetric

import javax.crypto.spec.{GCMParameterSpec, IvParameterSpec}
import javax.crypto.{Cipher => JCipher, SecretKey => JSecretKey}

import cats.evidence.Is
import tsec.cipher.common.padding.{NoPadding, PKCS7Padding, SymmetricPadding}
import tsec.cipher.symmetric.core.{Iv, IvStrategy}
import tsec.cipher.symmetric.imports.primitive.JCAPrimitiveCipher
import tsec.common.JKeyGenerator

package object imports {

  trait Cipher[A] {
    def cipherName: String
    def blockSizeBytes: Int
    def keySizeBytes: Int
  }

  trait BlockCipher[A] extends Cipher[A]

  trait AES[A] extends BlockCipher[A] {
    val cipherName: String  = "AES"
    val blockSizeBytes: Int = 16
  }

  /**
    * This trait propagates type information about a parametrized T being a symmetric cipher mode of operation
    * @tparam T
    */
  trait CipherMode[T] {
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
      implicit cipher: Cipher[A]
  ): IvProcess[A, M, P, SecretKey] =
    new IvProcess[A, M, P, SecretKey] {

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
    implicit def cbcProcess[A, P: SymmetricPadding](implicit cipher: Cipher[A]): IvProcess[A, CBC, P, SecretKey] =
      standardProcess[A, CBC, P]
  }

  sealed trait CFB

  object CFB extends WithCipherMode[CFB]("CFB") {
    implicit def cfbProcess[A](implicit cipher: Cipher[A]): IvProcess[A, CFB, NoPadding, SecretKey] =
      standardProcess[A, CFB, NoPadding]
  }

  sealed trait CFBx

  object CFBx extends WithCipherMode[CFBx]("CFBx") {
    implicit def cfbxProcess[A](implicit cipher: Cipher[A]): IvProcess[A, CFBx, NoPadding, SecretKey] =
      standardProcess[A, CFBx, NoPadding]
  }

  sealed trait CTR

  object CTR extends WithCipherMode[CTR]("CTR") {
    implicit def ctrProcess[A, P: SymmetricPadding](
        implicit cipher: Cipher[A]
    ): IvProcess[A, CTR, P, SecretKey] =
      standardProcess[A, CTR, P]
  }

  sealed trait ECB

  object ECB extends WithCipherMode[ECB]("ECB") {
    implicit def ecbProcess[A: Cipher]: IvProcess[A, ECB, NoPadding, SecretKey] =
      new IvProcess[A, ECB, NoPadding, SecretKey] {
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
    val TagLengthBits     = 128
    val NISTIvLengthBytes = 12

    implicit def gcmProcess[A](implicit aes: AES[A]): IvProcess[A, GCM, NoPadding, SecretKey] =
      new IvProcess[A, GCM, NoPadding, SecretKey] {
        private[tsec] def encryptInit(cipher: JCipher, iv: Iv[A, GCM], key: SecretKey[A]): Unit =
          cipher.init(
            JCipher.ENCRYPT_MODE,
            key.toJavaKey,
            new GCMParameterSpec(GCM.TagLengthBits, iv)
          )

        private[tsec] def decryptInit(cipher: JCipher, iv: Iv[A, GCM], key: SecretKey[A]): Unit =
          cipher.init(
            JCipher.DECRYPT_MODE,
            key.toJavaKey,
            new GCMParameterSpec(GCM.TagLengthBits, iv)
          )
      }
  }

  sealed trait NoMode

  object NoMode extends WithCipherMode[NoMode]("NoMode") {
    implicit def noModeProcess[A: Cipher]: IvProcess[A, NoMode, NoPadding, SecretKey] =
      new IvProcess[A, NoMode, NoPadding, SecretKey] {
        private[tsec] def encryptInit(cipher: JCipher, iv: Iv[A, NoMode], key: SecretKey[A]): Unit =
          cipher.init(JCipher.ENCRYPT_MODE, key.toJavaKey)

        private[tsec] def decryptInit(cipher: JCipher, iv: Iv[A, NoMode], key: SecretKey[A]): Unit =
          cipher.init(JCipher.DECRYPT_MODE, key.toJavaKey)
      }
  }

  sealed trait OFB

  object OFB extends WithCipherMode[OFB]("OFB") {
    implicit def ofbProcess[A](implicit cipher: Cipher[A]): IvProcess[A, OFB, NoPadding, SecretKey] =
      standardProcess[A, OFB, NoPadding]
  }

  sealed trait OFBx

  object OFBx extends WithCipherMode[OFBx]("OFBx") {
    implicit def ofbxProcess[A](implicit cipher: Cipher[A]): IvProcess[A, OFBx, NoPadding, SecretKey] =
      standardProcess[A, OFBx, NoPadding]
  }

  sealed trait PCBC

  object PCBC extends WithCipherMode[PCBC]("PCBC") {
    implicit def pcbcProcess[A, P: SymmetricPadding](implicit cipher: Cipher[A]): IvProcess[A, PCBC, P, SecretKey] =
      standardProcess[A, PCBC, P]
  }

  type AESGCMEncrypted[A] = CipherText[A, GCM, NoPadding]

  type CBCEncrypted[A] = CipherText[A, CBC, PKCS7Padding]

  type CBCIVStrategy[A] = IvStrategy[A, CBC]

  type CBCCipher[F[_], C] = JCAPrimitiveCipher[F, C, CBC, PKCS7Padding]

  type CTREncrypted[A] = CipherText[A, CTR, NoPadding]

}
