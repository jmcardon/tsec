package tsec.cipher.asymmetric.core

import tsec.cipher.common._

trait AsymmetricCipherAlgebra[F[_], A, M, P, K, O] {
  type C

  def genInstance: F[C]

  def encrypt(plainText: PlainText, key: PrivateKey[K]): F[CipherText[A, M, P]]

  def decrypt(cipherText: CipherText[A, M, P], key: PublicKey[O]): F[PlainText]

}
