package tsec.cipher.symmetric.core

import cats.effect.Sync
import tsec.cipher.symmetric.{AAD, AuthTag, PlainText}

/** Our high level cipher algebra,
  * wherein the implicit Scala cipher is placed
  * as a type parameter for future libsodium algebra compatibility
  *
  * @tparam A The cipher algorithm
  * @tparam M mode of operation
  * @tparam P Padding type
  * @tparam CT CipherText type alias
  * @tparam K Key type constructor
  * @tparam SCipher Cipher type constructor
  */
trait HLCipherAlgebra[A, M, P, CT, K[_], SCipher[_[_]]] {

  def encrypt[F[_]](plainText: PlainText, key: K[A])(
      implicit F: Sync[F],
      S: SCipher[F],
      ivStrategy: IvStrategy[A, M]
  ): F[CT]

  def encrypt[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A, M])(
      implicit F: Sync[F],
      S: SCipher[F],
  ): F[CT] = encrypt[F](plainText, key)(F, S, ivs)

  def encrypt[F[_]](plainText: PlainText, key: K[A], iv: Iv[A, M])(
      implicit F: Sync[F],
      S: SCipher[F],
  ): F[CT]

  def decrypt[F[_]](cipherText: CT, key: K[A])(
      implicit F: Sync[F],
      S: SCipher[F]
  ): F[PlainText]

}

//Todo: Generalize over separated auth tags.
/** Our AEAD algebra **/
trait HLAEADAlgebra[A, M, P, CT, K[_], SCipher[_[_]]] extends HLCipherAlgebra[A, M, P, CT, K, SCipher] {

  def encryptDetached[F[_]](plainText: PlainText, key: K[A])(
    implicit F: Sync[F],
    S: SCipher[F],
    ivStrategy: IvStrategy[A, M]
  ): F[(CT, AuthTag[A])]

  def encryptDetached[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A, M])(
    implicit F: Sync[F],
    S: SCipher[F],
  ): F[(CT, AuthTag[A])] = encryptDetached[F](plainText, key)(F, S, ivs)

  def encryptDetached[F[_]](plainText: PlainText, key: K[A], iv: Iv[A, M])(
    implicit F: Sync[F],
    S: SCipher[F],
  ): F[(CT, AuthTag[A])]

  def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: SCipher[F],
      ivStrategy: IvStrategy[A, M]
  ): F[CT]

  def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A, M], aad: AAD)(
      implicit F: Sync[F],
      S: SCipher[F],
  ): F[CT] = encryptWithAAD[F](plainText, key, aad)(F, S, ivs)

  def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], iv: Iv[A, M], aad: AAD)(
      implicit F: Sync[F],
      S: SCipher[F],
  ): F[CT]

  def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: SCipher[F],
      ivStrategy: IvStrategy[A, M]
  ): F[(CT, AuthTag[A])]

  def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A, M], aad: AAD)(
      implicit F: Sync[F],
      S: SCipher[F],
  ): F[(CT, AuthTag[A])] = encryptWithAADDetached[F](plainText, key, aad)(F, S, ivs)

  def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], iv: Iv[A, M], aad: AAD)(
      implicit F: Sync[F],
      S: SCipher[F],
  ): F[(CT, AuthTag[A])]

  def decryptDetached[F[_]](cipherText: CT, key: K[A], authTag: AuthTag[A])(
    implicit F: Sync[F],
    S: SCipher[F]
  ): F[PlainText]

  def decryptWithAAD[F[_]](cipherText: CT, key: K[A], aad: AAD)(
      implicit F: Sync[F],
      S: SCipher[F]
  ): F[PlainText]

  def decryptWithAADDetached[F[_]](cipherText: CT, key: K[A], aad: AAD, authTag: AuthTag[A])(
    implicit F: Sync[F],
    S: SCipher[F]
  ): F[PlainText]

}
