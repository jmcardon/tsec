package tsec.cipher.symmetric.jca.primitive

import java.util.{Arrays => JaRule}
import javax.crypto.{Cipher => JCipher}

import cats.MonadError
import cats.effect.Sync
import cats.syntax.all._
import tsec.cipher.common.padding.SymmetricPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.jca._

sealed abstract class JCAAEADPrimitive[F[_], A, M, P](
    implicit algoTag: BlockCipher[A],
    aead: AEADCipher[A],
    modeSpec: CipherMode[M],
    paddingTag: SymmetricPadding[P],
    F: MonadError[F, Throwable],
    private[tsec] val ivProcess: IvProcess[A, M, P]
) extends AADEncryptor[F, A, SecretKey] {

  private def getInstance: JCipher =
    JCAPrimitiveCipher.getJCipherUnsafe[A, M, P]

  private[tsec] def catchF[Y](a: => Y): F[Y]

  def encrypt(plainText: PlainText, key: SecretKey[A], iv: Iv[A]): F[CipherText[A]] =
    catchF {
      val instance = getInstance
      ivProcess.encryptInit(instance, iv, key.toJavaKey)
      val encrypted = instance.doFinal(plainText)
      CipherText[A](RawCipherText(encrypted), iv)
    }

  def decrypt(cipherText: CipherText[A], key: SecretKey[A]): F[PlainText] =
    catchF {
      val instance = getInstance
      ivProcess.decryptInit(instance, cipherText.nonce, key.toJavaKey)
      val out = instance.doFinal(cipherText.content)
      PlainText(out)
    }

  def encryptWithAAD(plainText: PlainText, key: SecretKey[A], iv: Iv[A], aad: AAD): F[CipherText[A]] =
    catchF {
      val instance = getInstance
      ivProcess.encryptInit(instance, iv, key.toJavaKey)
      instance.updateAAD(aad)
      val encrypted = RawCipherText[A](instance.doFinal(plainText))
      CipherText[A](encrypted, iv)
    }

  def decryptWithAAD(cipherText: CipherText[A], key: SecretKey[A], aad: AAD): F[PlainText] =
    catchF {
      val instance = getInstance
      ivProcess.decryptInit(instance, cipherText.nonce, key.toJavaKey)
      instance.updateAAD(aad)
      val out = instance.doFinal(cipherText.content)
      PlainText(out)
    }

  def encryptDetached(plainText: PlainText, key: SecretKey[A], iv: Iv[A]): F[(CipherText[A], AuthTag[A])] =
    catchF {
      val instance = getInstance
      ivProcess.encryptInit(instance, iv, key.toJavaKey)
      val encrypted  = instance.doFinal(plainText)
      val cipherText = RawCipherText[A](JaRule.copyOfRange(encrypted, 0, encrypted.length - aead.tagSizeBytes))
      val tag        = JaRule.copyOfRange(encrypted, encrypted.length - aead.tagSizeBytes, encrypted.length)
      (CipherText[A](cipherText, iv), AuthTag[A](tag))
    }

  def decryptDetached(cipherText: CipherText[A], key: SecretKey[A], tag: AuthTag[A]): F[PlainText] =
    if (tag.length != aead.tagSizeBytes)
      F.raiseError(AuthTagError("Authentication tag of incorrect length"))
    else
      catchF {
        val instance = getInstance
        ivProcess.decryptInit(instance, cipherText.nonce, key.toJavaKey)
        //Re-combine the auth tag and the ciphertext, because thx JCA
        val combined = new Array[Byte](aead.tagSizeBytes + cipherText.content.length)
        System.arraycopy(cipherText.content, 0, combined, 0, cipherText.content.length)
        System.arraycopy(tag, 0, combined, cipherText.content.length, tag.length)

        val out = instance.doFinal(combined)
        PlainText(out)
      }

  def encryptWithAADDetached(
      plainText: PlainText,
      key: SecretKey[A],
      iv: Iv[A],
      aad: AAD
  ): F[(CipherText[A], AuthTag[A])] =
    catchF {
      val instance = getInstance
      ivProcess.encryptInit(instance, iv, key.toJavaKey)
      instance.updateAAD(aad)
      val encrypted  = instance.doFinal(plainText)
      val cipherText = RawCipherText[A](JaRule.copyOfRange(encrypted, 0, encrypted.length - aead.tagSizeBytes))
      val tag        = JaRule.copyOfRange(encrypted, encrypted.length - aead.tagSizeBytes, encrypted.length)
      (CipherText[A](cipherText, iv), AuthTag[A](tag))
    }

  def decryptWithAADDetached(cipherText: CipherText[A], key: SecretKey[A], aad: AAD, tag: AuthTag[A]): F[PlainText] =
    if (tag.length != aead.tagSizeBytes)
      F.raiseError(AuthTagError("Authentication tag of incorrect length"))
    else
      catchF {
        val instance = getInstance
        ivProcess.decryptInit(instance, cipherText.nonce, key.toJavaKey)

        //Re-combine the auth tag and the ciphertext, because thx JCA
        val combined = new Array[Byte](aead.tagSizeBytes + cipherText.content.length)
        System.arraycopy(cipherText.content, 0, combined, 0, cipherText.content.length)
        System.arraycopy(tag, 0, combined, cipherText.content.length, tag.length)

        instance.updateAAD(aad)
        val out = instance.doFinal(combined)
        PlainText(out)
      }

}

object JCAAEADPrimitive {

  private[tsec] def sync[F[_], A: BlockCipher: AEADCipher, M: CipherMode, P: SymmetricPadding](
      implicit F: Sync[F],
      ivProcess: IvProcess[A, M, P]
  ): AADEncryptor[F, A, SecretKey] =
    new JCAAEADPrimitive[F, A, M, P] {
      private[tsec] def catchF[C](thunk: => C): F[C] = F.delay(thunk)
    }

  private[tsec] def monadError[F[_], A: BlockCipher: AEADCipher, M: CipherMode, P: SymmetricPadding](
      implicit F: MonadError[F, Throwable],
      ivProcess: IvProcess[A, M, P]
  ): JCAAEADPrimitive[F, A, M, P] =
    new JCAAEADPrimitive[F, A, M, P] {
      private[tsec] def catchF[C](thunk: => C): F[C] =
        F.catchNonFatal(thunk)
    }
}
