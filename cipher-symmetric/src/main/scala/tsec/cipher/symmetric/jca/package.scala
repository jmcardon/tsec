package tsec.cipher.symmetric

import javax.crypto.spec.{GCMParameterSpec, IvParameterSpec}
import javax.crypto.{Cipher => JCipher, SecretKey => JSecretKey}

import cats.effect.Sync
import tsec.cipher.CipherErrors
import tsec.cipher.common.padding._
import tsec.common.ManagedRandom

package object jca extends CipherErrors {

  type SecretKey[A] = SecretKey.Type[A]

  object SecretKey {
    type Base[A]
    trait M$$ extends Any

    type Type[A] <: Base[A] with M$$

    def apply[A](key: JSecretKey): SecretKey[A]     = key.asInstanceOf[SecretKey[A]]
    def toJavaKey[A](key: SecretKey[A]): JSecretKey = key.asInstanceOf[JSecretKey]
    def subst[A]: SecretKPartiallyApplied[A]        = new SecretKPartiallyApplied[A]

    private[tsec] class SecretKPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[JSecretKey]): F[SecretKey[A]] = value.asInstanceOf[F[SecretKey[A]]]
    }

    def unsubst[A]: SecretKUnwrap[A] = new SecretKUnwrap[A]

    private[tsec] class SecretKUnwrap[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[SecretKey[A]]): F[JSecretKey] = value.asInstanceOf[F[JSecretKey]]
    }
  }

  final class SecretKeySyntax[A](val key: SecretKey[A]) extends AnyVal {
    @inline def toJavaKey: JSecretKey = SecretKey.toJavaKey(key)
    def getEncoded: Array[Byte]       = toJavaKey.getEncoded
  }

  implicit final def _secretKeySyntax[A](key: SecretKey[A]) = new SecretKeySyntax[A](key)

  class WithCipherMode[M](val mode: String) extends CipherMode[M] {
    implicit val m: CipherMode[M] = this
  }

  private[tsec] def standardProcess[A, M, P: SymmetricPadding](
      implicit cipher: BlockCipher[A]
  ): IvProcess[A, M, P] =
    new IvProcess[A, M, P] {

      val ivLengthBytes: Int = cipher.blockSizeBytes

      private[tsec] def encryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
        cipher.init(
          JCipher.ENCRYPT_MODE,
          key,
          new IvParameterSpec(iv)
        )

      private[tsec] def decryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
        cipher.init(
          JCipher.DECRYPT_MODE,
          key,
          new IvParameterSpec(iv)
        )
    }

  /*
  Modes of operation
   */
  sealed trait CBC

  object CBC extends WithCipherMode[CBC]("CBC") {
    implicit def cbcProcess[A, P: SymmetricPadding](implicit cipher: BlockCipher[A]): IvProcess[A, CBC, P] =
      standardProcess[A, CBC, P]
  }

  sealed trait CFB

  object CFB extends WithCipherMode[CFB]("CFB") {
    implicit def cfbProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, CFB, NoPadding] =
      standardProcess[A, CFB, NoPadding]
  }

  sealed trait CFBx

  object CFBx extends WithCipherMode[CFBx]("CFBx") {
    implicit def cfbxProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, CFBx, NoPadding] =
      standardProcess[A, CFBx, NoPadding]
  }

  sealed trait CTR

  object CTR extends WithCipherMode[CTR]("CTR") {
    implicit def ctrProcess[A, P: SymmetricPadding](
        implicit cipher: BlockCipher[A]
    ): IvProcess[A, CTR, P] =
      standardProcess[A, CTR, P]
  }

  sealed trait ECB

  object ECB extends WithCipherMode[ECB]("ECB") {
    implicit def ecbProcess[A: BlockCipher]: IvProcess[A, ECB, NoPadding] =
      new IvProcess[A, ECB, NoPadding] {

        val ivLengthBytes: Int = 0

        private[tsec] def encryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
          cipher.init(JCipher.ENCRYPT_MODE, key)

        private[tsec] def decryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
          cipher.init(JCipher.DECRYPT_MODE, key)

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

    implicit def gcmProcess[A](implicit aes: AES[A]): IvProcess[A, GCM, NoPadding] =
      new IvProcess[A, GCM, NoPadding] {

        val ivLengthBytes: Int = NISTIvLengthBytes

        private[tsec] def encryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
          cipher.init(
            JCipher.ENCRYPT_MODE,
            key,
            new GCMParameterSpec(GCM.NISTTagLengthBits, iv)
          )

        private[tsec] def decryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
          cipher.init(
            JCipher.DECRYPT_MODE,
            key,
            new GCMParameterSpec(GCM.NISTTagLengthBits, iv)
          )

      }

    def randomIVStrategy[F[_], Out: AES](implicit F: Sync[F]): IvGen[F, Out] =
      new IvGen[F, Out] with ManagedRandom {

        def genIv: F[Iv[Out]] =
          F.delay(genIvUnsafe)

        def genIvUnsafe: Iv[Out] = {
          val nonce = new Array[Byte](GCM.NISTIvLengthBytes)
          nextBytes(nonce)
          Iv[Out](nonce)
        }
      }

  }

  sealed trait NoMode

  object NoMode extends WithCipherMode[NoMode]("NoMode") {
    implicit def noModeProcess[A: BlockCipher]: IvProcess[A, NoMode, NoPadding] =
      new IvProcess[A, NoMode, NoPadding] {

        val ivLengthBytes: Int = 0

        private[tsec] def encryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
          cipher.init(JCipher.ENCRYPT_MODE, key)

        private[tsec] def decryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit =
          cipher.init(JCipher.DECRYPT_MODE, key)
      }
  }

  sealed trait OFB

  object OFB extends WithCipherMode[OFB]("OFB") {
    implicit def ofbProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, OFB, NoPadding] =
      standardProcess[A, OFB, NoPadding]
  }

  sealed trait OFBx

  object OFBx extends WithCipherMode[OFBx]("OFBx") {
    implicit def ofbxProcess[A](implicit cipher: BlockCipher[A]): IvProcess[A, OFBx, NoPadding] =
      standardProcess[A, OFBx, NoPadding]
  }

  sealed trait PCBC

  object PCBC extends WithCipherMode[PCBC]("PCBC") {
    implicit def pcbcProcess[A, P: SymmetricPadding](
        implicit cipher: BlockCipher[A]
    ): IvProcess[A, PCBC, P] =
      standardProcess[A, PCBC, P]
  }

  object CTOPS {
    private[tsec] def ciphertextFromArray[A, M, P](
        bytes: Array[Byte]
    )(implicit spec: IvProcess[A, M, P], blockCipher: BlockCipher[A]): Either[CipherTextError, CipherText[A]] =
      if (bytes.length < spec.ivLengthBytes + 1)
        Left(CipherTextError("Array must be nonEmpty"))
      else {
        val ivIx         = bytes.length - spec.ivLengthBytes
        val ivArray      = new Array[Byte](spec.ivLengthBytes)
        val contentArray = new Array[Byte](ivIx)
        System.arraycopy(bytes, 0, contentArray, 0, ivIx)
        System.arraycopy(bytes, ivIx, ivArray, 0, spec.ivLengthBytes)

        Right(CipherText[A](RawCipherText(contentArray), Iv(ivArray)))
      }
  }

  type JEncryptor[F[_], A]     = Encryptor[F, A, SecretKey]
  type JAuthEncryptor[F[_], A] = AADEncryptor[F, A, SecretKey]

}
