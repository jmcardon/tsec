package tsec.cipher.core

trait CipherAlgebra[F[_], A, M, P, K] {
  type C
  
  def genInstance: () => C

  def encrypt(clearText: PlainText[A, M, P], key: SecretKey[K], encryptor: C): F[CipherText[A, M, P]]

  def decrypt(cipherText: CipherText[A, M, P], key: SecretKey[K], decryptor: C): F[PlainText[A, M, P]]

}
