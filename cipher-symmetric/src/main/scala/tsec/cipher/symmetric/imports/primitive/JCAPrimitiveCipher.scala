package tsec.cipher.symmetric.imports.primitive

import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import javax.crypto.{Cipher => JCipher}

import cats.effect.Sync
import cats.syntax.all._
import tsec.cipher.common.padding.SymmetricPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.{CipherAlgebra, Iv}
import tsec.cipher.symmetric.imports.{BlockCipher, CipherMode, IvProcess, SecretKey}

sealed abstract class JCAPrimitiveCipher[F[_], A, M, P](private val queue: JQueue[JCipher])(
    implicit algoTag: BlockCipher[A],
    modeSpec: CipherMode[M],
    paddingTag: SymmetricPadding[P],
    private[tsec] val ivProcess: IvProcess[A, M, P, SecretKey],
    F: Sync[F]
) extends CipherAlgebra[F, A, M, P, SecretKey] {

  private def getInstance = {
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
      val encrypted = instance.doFinal(plainText)
      reQueue(instance)
      CipherText[A, M, P](encrypted, iv)
    }

  def decrypt(cipherText: CipherText[A, M, P], key: SecretKey[A]): F[PlainText] = F.delay {
    val instance = getInstance
    ivProcess.decryptInit(instance, Iv[A, M](cipherText.iv), key)
    val out = instance.doFinal(cipherText.content)
    reQueue(instance)
    PlainText(out)
  }
}

object JCAPrimitiveCipher {
  private[tsec] def getJCipherUnsafe[A, M, P](
      implicit algoTag: BlockCipher[A],
      modeSpec: CipherMode[M],
      paddingTag: SymmetricPadding[P]
  ): JCipher = JCipher.getInstance(s"${algoTag.cipherName}/${modeSpec.mode}/${paddingTag.algorithm}")

  private[tsec] def genQueueUnsafe[A: BlockCipher, M: CipherMode, P: SymmetricPadding](
      queueLen: Int
  ): JQueue[JCipher] = {
    val q = new JQueue[JCipher]()
    Array
      .range(0, queueLen)
      .foreach(
        _ => q.add(getJCipherUnsafe)
      )
    q
  }

  def apply[F[_], A: BlockCipher, M: CipherMode, P: SymmetricPadding](
      queueSize: Int = 15
  )(implicit F: Sync[F], ivProcess: IvProcess[A, M, P, SecretKey]): F[JCAPrimitiveCipher[F, A, M, P]] =
    F.delay(genQueueUnsafe(queueSize)).map(new JCAPrimitiveCipher[F, A, M, P](_) {})
}
