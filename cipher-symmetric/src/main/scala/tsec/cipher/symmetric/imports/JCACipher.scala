package tsec.cipher.symmetric.imports

import cats.effect.Sync
import cats.evidence.Is
import cats.syntax.all._
import tsec.cipher.symmetric
import tsec.cipher.symmetric.CipherText
import tsec.cipher.symmetric.core.{HLCipherAlgebra, IvStrategy}
import tsec.cipher.symmetric.imports.primitive.JCAPrimitiveCipher

sealed abstract class JCACipher[A, M, P, CT](
    implicit ev: CT =:= CipherText[A, M, P]
) extends HLCipherAlgebra[A, M, P, CT, SecretKey, JCAPrimitiveCipher[?[_], A, M, P]] {
  private val is = Is.unsafeFromPredef[CT, CipherText[A, M, P]](ev).flip

  def encrypt[F[_]](
      plainText: symmetric.PlainText,
      key: SecretKey[A]
  )(implicit F: Sync[F], scalaCipher: JCAPrimitiveCipher[F, A, M, P], ivStrategy: IvStrategy[A, M]): F[CT] =
    for {
      iv        <- ivStrategy.genIv[F]
      encrypted <- scalaCipher.encrypt(plainText, key, iv)
    } yield is.coerce(encrypted)

  def decrypt[F[_]](cipherText: CT, key: SecretKey[A])(
      implicit F: Sync[F],
      scalaCipher: JCAPrimitiveCipher[F, A, M, P]
  ): F[symmetric.PlainText] = scalaCipher.decrypt(cipherText, key)
}
