package tsec.cipher.symmetric.imports

import cats.effect.Sync
import cats.evidence.Is
import cats.syntax.all._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core.{HLAEADAlgebra, Iv, IvStrategy}
import tsec.cipher.symmetric.imports.primitive.JCAAEADPrimitive

class JCAAEAD[A, M, P, CT](implicit ev: CT =:= CipherText[A, M, P])
    extends HLAEADAlgebra[A, M, P, CT, SecretKey, JCAAEADPrimitive[?[_], A, M, P]] {
  private val is = Is.unsafeFromPredef[CT, CipherText[A, M, P]](ev).flip

  def encrypt[F[_]](
      plainText: PlainText,
      key: SecretKey[A]
  )(implicit F: Sync[F], S: JCAAEADPrimitive[F, A, M, P], ivStrategy: IvStrategy[A, M]): F[CT] =
    for {
      iv        <- ivStrategy.genIv[F](plainText.content.length)
      encrypted <- S.encrypt(plainText, key, iv)
    } yield is.coerce(encrypted)

  def encrypt[F[_]](plainText: PlainText, key: SecretKey[A], iv: Iv[A, M])(
      implicit F: Sync[F],
      S: JCAAEADPrimitive[F, A, M, P]
  ): F[CT] = is.substitute[F](S.encrypt(plainText, key, iv))

  def decrypt[F[_]](cipherText: CT, key: SecretKey[A])(
      implicit F: Sync[F],
      S: JCAAEADPrimitive[F, A, M, P]
  ): F[PlainText] = S.decrypt(cipherText, key)

  def encryptWithAAD[F[_]](plainText: PlainText, key: SecretKey[A], aad: AAD)(
      implicit F: Sync[F],
      S: JCAAEADPrimitive[F, A, M, P],
      ivStrategy: IvStrategy[A, M]
  ): F[CT] =
    for {
      iv        <- ivStrategy.genIv[F](plainText.content.length)
      encrypted <- S.encryptAAD(plainText, key, iv, aad)
    } yield is.coerce(encrypted)

  def encryptWithAAD[F[_]](plainText: PlainText, key: SecretKey[A], iv: Iv[A, M], aad: AAD)(
      implicit F: Sync[F],
      S: JCAAEADPrimitive[F, A, M, P]
  ): F[CT] = is.substitute[F](S.encryptAAD(plainText, key, iv, aad))

  def decryptWithAAD[F[_]](cipherText: CT, key: SecretKey[A], aad: AAD)(
      implicit F: Sync[F],
      S: JCAAEADPrimitive[F, A, M, P]
  ): F[PlainText] = S.decryptAAD(cipherText, key, aad)
}
