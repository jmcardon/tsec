package tsec.cipher.symmetric.core

import cats.effect.Sync
import tsec.cipher.symmetric.PlainText

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
trait HLCipherAlgebra[A, M, P, CT, K[_], SCipher[_[_]]]{

  def encrypt[F[_]](plainText: PlainText, key: K[A])(
      implicit F: Sync[F],
      scalaCipher: SCipher[F],
      ivStrategy: IvStrategy[A, M]
  ): F[CT]

  def encryptWithStrategy[F[_]](plainText: PlainText, key: K[A], ivs: IvStrategy[A, M])(
      implicit F: Sync[F],
      scalaCipher: SCipher[F],
  ): F[CT] = encrypt[F](plainText, key)(F, scalaCipher, ivs)

  def decrypt[F[_]](cipherText: CT, key: K[A])(
      implicit F: Sync[F],
      scalaCipher: SCipher[F]
  ): F[PlainText]

}