package tsec.cipher.symmetric.imports.primitive

import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import javax.crypto.{Cipher => JCipher}

import cats.effect.Sync
import cats.syntax.all._
import tsec.cipher.common.padding.SymmetricPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.{AEADAlgebra, Iv}
import tsec.cipher.symmetric.imports._

sealed abstract class JCAAEADPrimitive[F[_], A, M, P](private val queue: JQueue[JCipher])(
    implicit algoTag: BlockCipher[A],
    aead: AEADCipher[A],
    modeSpec: CipherMode[M],
    paddingTag: SymmetricPadding[P],
    ivProcess: IvProcess[A, M, P, SecretKey],
    F: Sync[F]
) extends AEADAlgebra[F, A, M, P, SecretKey] {

  private def getInstance: JCipher = {
    val instance = queue.poll()
    if (instance != null)
      instance
    else
      JCAPrimitiveCipher.getJCipherUnsafe[A, M, P]
  }

  private def reQueue(instance: JCipher) = queue.add(instance)

  def encrypt(plainText: PlainText, key: SecretKey[A], iv: Iv[A, M]): F[CipherText[A, M, P]] =
    F.delay {
      val instance = getInstance
      ivProcess.encryptInit(instance, iv, key)
      val encrypted = instance.doFinal(plainText.content)
      reQueue(instance)
      CipherText[A, M, P](encrypted, iv)
    }

  def decrypt(cipherText: CipherText[A, M, P], key: SecretKey[A]): F[PlainText] =
    F.delay {
      val instance = getInstance
      ivProcess.decryptInit(instance, Iv[A, M](cipherText.iv), key)
      val out = instance.doFinal(cipherText.content)
      reQueue(instance)
      PlainText(out)
    }

  def encryptAAD(plainText: PlainText, key: SecretKey[A], iv: Iv[A, M], aad: AAD): F[CipherText[A, M, P]] =
    F.delay {
      val instance = getInstance
      ivProcess.encryptInit(instance, iv, key)
      instance.updateAAD(aad.aad)
      val encrypted = instance.doFinal(plainText.content)
      reQueue(instance)
      CipherText[A, M, P](encrypted, iv)
    }

  def decryptAAD(cipherText: CipherText[A, M, P], key: SecretKey[A], aad: AAD): F[PlainText] =
    F.delay {
      val instance = getInstance
      ivProcess.decryptInit(instance, Iv[A, M](cipherText.iv), key)
      instance.updateAAD(aad.aad)
      val out = instance.doFinal(cipherText.content)
      reQueue(instance)
      PlainText(out)
    }

}

object JCAAEADPrimitive {

  def apply[F[_], A: BlockCipher: AEADCipher, M: CipherMode, P: SymmetricPadding](
    queueSize: Int = 15
  )(implicit F: Sync[F], ivProcess: IvProcess[A, M, P, SecretKey]): F[JCAAEADPrimitive[F, A, M, P]] =
    F.delay(JCAPrimitiveCipher.genQueueUnsafe[A, M, P](queueSize))
      .map(new JCAAEADPrimitive[F, A, M, P](_) {})
}
