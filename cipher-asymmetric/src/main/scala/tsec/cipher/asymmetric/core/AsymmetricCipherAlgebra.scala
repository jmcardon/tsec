package tsec.cipher.asymmetric.core

import tsec.cipher.asymmetric.imports._
import tsec.cipher.common.mode.NoMode
import tsec.cipher.common.{CipherText, PlainText}

trait AsymmetricCipherAlgebra[F[_], A, P] {
  type C

  def genInstance: F[C]

  def encrypt(plainText: PlainText, key: PublicKey[A]): F[CipherText[A, NoMode, P]]

  def decrypt(cipherText: CipherText[A, NoMode, P], key: PrivateKey[A]): F[PlainText]
}
