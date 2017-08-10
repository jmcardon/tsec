package tsec.cipher.core

import cats.Monad

abstract class CipherPrograms[F[_]: Monad, A, M, P, K[_]](algebra: CipherAlgebra[F, A, M, P, K]) {

  def encrypt(clearText: PlainText[A,M,P], key: SecretKey[K[A]]): F[CipherText[A, M, P]] = {
    algebra.encrypt(clearText, key, algebra.genInstance())
  }

  def decrypt(cipherText: CipherText[A, M, P], key: SecretKey[K[A]]): F[PlainText[A, M, P]] = {
    algebra.decrypt(cipherText, key, algebra.genInstance())
  }

}
