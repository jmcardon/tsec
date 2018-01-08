package tsec.cipher.symmetric.imports

import javax.crypto.{Cipher => JCipher}

import tsec.cipher.symmetric.core.Iv

private[tsec] trait IvProcess[C, M, P, K[_]] {

  def ivLengthBytes: Int

  private[tsec] def encryptInit(cipher: JCipher, iv: Iv[C, M], key: K[C]): Unit

  private[tsec] def decryptInit(cipher: JCipher, iv: Iv[C, M], key: K[C]): Unit
}