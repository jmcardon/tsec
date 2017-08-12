package tsec.cipher.core

trait CipherAlgebra[F[_], A, M, P, K[_]] {
  type C

  def genInstance: F[C]

  def encrypt(clearText: PlainText[A, M, P], key: SecretKey[K[A]]): F[CipherText[A, M, P]]

  def encryptAAD(clearText: PlainText[A, M, P], key: SecretKey[K[A]], aad: AAD): F[CipherText[A, M, P]]

  def decrypt(cipherText: CipherText[A, M, P], key: SecretKey[K[A]]): F[PlainText[A, M, P]]

  def decryptAAD(cipherText: CipherText[A, M, P], key: SecretKey[K[A]], aad: AAD): F[PlainText[A, M, P]]

}
