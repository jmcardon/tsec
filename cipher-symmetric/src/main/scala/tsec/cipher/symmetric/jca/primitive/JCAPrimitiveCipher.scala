package tsec.cipher.symmetric.jca.primitive

import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import javax.crypto.{Cipher => JCipher}

import cats.MonadError
import cats.effect.Sync
import cats.syntax.all._
import tsec.cipher.common.padding.SymmetricPadding
import tsec.cipher.symmetric.{Encryptor, _}
import tsec.cipher.symmetric.jca.{IvProcess, SecretKey}

sealed abstract class JCAPrimitiveCipher[F[_], C, M, P](
    implicit algoTag: BlockCipher[C],
    modeSpec: CipherMode[M],
    paddingTag: SymmetricPadding[P],
    private[tsec] val ivProcess: IvProcess[C, M, P]
) extends Encryptor[F, C, SecretKey] {

  private[tsec] def catchF[Y](a: => Y): F[Y]

  private def getInstance =
    JCAPrimitiveCipher.getJCipherUnsafe[C, M, P]

  def encrypt(plainText: PlainText, key: SecretKey[C], iv: Iv[C]): F[CipherText[C]] =
    catchF {
      val instance = getInstance
      ivProcess.encryptInit(instance, iv, key.toJavaKey)
      val encrypted = instance.doFinal(plainText)
      CipherText[C](RawCipherText(encrypted), iv)
    }

  def decrypt(cipherText: CipherText[C], key: SecretKey[C]): F[PlainText] = catchF {
    val instance = getInstance
    ivProcess.decryptInit(instance, cipherText.nonce, key.toJavaKey)
    val out = instance.doFinal(cipherText.content)
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

  def sync[F[_], A: BlockCipher, M: CipherMode, P: SymmetricPadding](
      implicit F: Sync[F],
      ivProcess: IvProcess[A, M, P]
  ): JCAPrimitiveCipher[F, A, M, P] =
    new JCAPrimitiveCipher[F, A, M, P] {
      private[tsec] def catchF[C](thunk: => C): F[C] = F.delay(thunk)
    }

  def monadError[F[_], A: BlockCipher, M: CipherMode, P: SymmetricPadding](
      implicit F: MonadError[F, Throwable],
      ivProcess: IvProcess[A, M, P]
  ): JCAPrimitiveCipher[F, A, M, P] =
    new JCAPrimitiveCipher[F, A, M, P] {
      private[tsec] def catchF[C](thunk: => C): F[C] = F.catchNonFatal(thunk)
    }
}
