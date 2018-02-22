package tsec.cipher.symmetric.imports

import javax.crypto.{Cipher => JCipher, SecretKey => JSecretKey}

private[tsec] trait IvProcess[C, M, P] {

  def ivLengthBytes: Int

  private[tsec] def encryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit

  private[tsec] def decryptInit(cipher: JCipher, iv: Array[Byte], key: JSecretKey): Unit
}
