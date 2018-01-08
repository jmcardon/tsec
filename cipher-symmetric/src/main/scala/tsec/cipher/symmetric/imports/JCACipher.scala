package tsec.cipher.symmetric.imports

import cats.effect.Sync
import cats.evidence.Is
import cats.syntax.all._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.{HLCipherAlgebra, Iv, IvStrategy}
import tsec.cipher.symmetric.imports.primitive.JCAPrimitiveCipher

private[tsec] abstract class JCACipher[A, M, P, CT](
    implicit ev: CT =:= CipherText[A, M, P]
) extends HLCipherAlgebra[A, M, P, CT, SecretKey, JCAPrimitiveCipher[?[_], A, M, P]] {
  private[tsec] val is = Is.unsafeFromPredef[CT, CipherText[A, M, P]](ev).flip

  def encrypt[F[_]](
      plainText: PlainText,
      key: SecretKey[A]
  )(implicit F: Sync[F], scalaCipher: JCAPrimitiveCipher[F, A, M, P], ivStrategy: IvStrategy[A, M]): F[CT] =
    for {
      iv        <- ivStrategy.genIv[F](plainText.content.length)
      encrypted <- scalaCipher.encrypt(plainText, key, iv)
    } yield is.coerce(encrypted)

  def encrypt[F[_]](plainText: PlainText, key: SecretKey[A], iv: Iv[A, M])(
      implicit F: Sync[F],
      scalaCipher: JCAPrimitiveCipher[F, A, M, P]
  ): F[CT] = is.substitute[F](scalaCipher.encrypt(plainText, key, iv))

  def decrypt[F[_]](cipherText: CT, key: SecretKey[A])(
      implicit F: Sync[F],
      scalaCipher: JCAPrimitiveCipher[F, A, M, P]
  ): F[PlainText] = scalaCipher.decrypt(cipherText, key)
}
