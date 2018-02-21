package tsec.cipher.symmetric.core

import cats.effect.Sync

/** Our high level cipher algebra,
  * wherein the implicit Scala cipher is placed
  * as a type parameter for future libsodium algebra compatibility
  *
  * @tparam A The cipher algorithm
  * @tparam K Key type constructor
  * @tparam S Cipher type constructor
  */
trait CipherAlgebra[A, K[_], S[_[_]]] {

  def encrypt[F[_]](plainText: PlainText, key: K[A])(
      implicit F: Sync[F],
      S: S[F],
      ivStrategy: IvStrategy[A]
  ): F[CipherText[A]]

  def encrypt[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A])(
      implicit F: Sync[F],
      S: S[F],
  ): F[CipherText[A]] = encrypt[F](plainText, key)(F, S, ivs)

  def encrypt[F[_]](plainText: PlainText, key: K[A], iv: Iv[A])(
      implicit F: Sync[F],
      S: S[F],
  ): F[CipherText[A]]

  def decrypt[F[_]](cipherText: CipherText[A], key: K[A])(
      implicit F: Sync[F],
      S: S[F]
  ): F[PlainText]

}

//Todo: Generalize over separated auth tags.
/** Our AEAD algebra **/
trait AEADAlgebra[A, K[_], S[_[_]]] extends CipherAlgebra[A, K, S] {

  def encryptDetached[F[_]](plainText: PlainText, key: K[A])(
      implicit F: Sync[F],
      S: S[F],
      ivStrategy: IvStrategy[A]
  ): F[(CipherText[A], AuthTag[A])]

  def encryptDetached[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A])(
      implicit F: Sync[F],
      S: S[F],
  ): F[(CipherText[A], AuthTag[A])] = encryptDetached[F](plainText, key)(F, S, ivs)

  def encryptDetached[F[_]](plainText: PlainText, key: K[A], iv: Iv[A])(
      implicit F: Sync[F],
      S: S[F],
  ): F[(CipherText[A], AuthTag[A])]

  def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: S[F],
      ivStrategy: IvStrategy[A]
  ): F[CipherText[A]]

  def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A], aad: AAD)(
      implicit F: Sync[F],
      S: S[F],
  ): F[CipherText[A]] = encryptWithAAD[F](plainText, key, aad)(F, S, ivs)

  def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], iv: Iv[A], aad: AAD)(
      implicit F: Sync[F],
      S: S[F],
  ): F[CipherText[A]]

  def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: S[F],
      ivStrategy: IvStrategy[A]
  ): F[(CipherText[A], AuthTag[A])]

  def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A], aad: AAD)(
      implicit F: Sync[F],
      S: S[F],
  ): F[(CipherText[A], AuthTag[A])] = encryptWithAADDetached[F](plainText, key, aad)(F, S, ivs)

  def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], iv: Iv[A], aad: AAD)(
      implicit F: Sync[F],
      S: S[F],
  ): F[(CipherText[A], AuthTag[A])]

  def decryptDetached[F[_]](cipherText: CipherText[A], key: K[A], authTag: AuthTag[A])(
      implicit F: Sync[F],
      S: S[F]
  ): F[PlainText]

  def decryptWithAAD[F[_]](cipherText: CipherText[A], key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: S[F]
  ): F[PlainText]

  def decryptWithAADDetached[F[_]](cipherText: CipherText[A], key: K[A], aad: AAD, authTag: AuthTag[A])(
      implicit F: Sync[F],
      S: S[F]
  ): F[PlainText]

}
