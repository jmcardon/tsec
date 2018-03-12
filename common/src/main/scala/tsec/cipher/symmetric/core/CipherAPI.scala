package tsec.cipher.symmetric.core

import cats.Monad
import cats.syntax.all._

/** Our high level cipher algebra,
  * wherein the implicit Scala cipher is placed
  * as a type parameter for future libsodium algebra compatibility
  *
  * @tparam A The cipher algorithm
  * @tparam K Key type constructor
  */
trait CipherAPI[A, K[_]] {

  final def encrypt[F[_]: Monad](plainText: PlainText, key: K[A])(
      implicit E: Encryptor[F, A, K],
      ivStrategy: IvGen[F, A]
  ): F[CipherText[A]] = ivStrategy.genIv.flatMap(encrypt[F](plainText, key, _))

  final def encrypt[F[_]: Monad](plainText: PlainText, key: K[A], ivs: IvGen[F, A])(
      E: Encryptor[F, A, K]
  ): F[CipherText[A]] = encrypt[F](plainText, key)(Monad[F], E, ivs)

  final def encrypt[F[_]](plainText: PlainText, key: K[A], iv: Iv[A])(
      implicit E: Encryptor[F, A, K]
  ): F[CipherText[A]] = E.encrypt(plainText, key, iv)

  final def decrypt[F[_]](cipherText: CipherText[A], key: K[A])(
      implicit E: Encryptor[F, A, K]
  ): F[PlainText] = E.decrypt(cipherText, key)
}

trait AuthCipherAPI[A, K[_]] extends CipherAPI[A, K] {

  final def encryptDetached[F[_]: Monad](plainText: PlainText, key: K[A])(
      implicit E: AuthEncryptor[F, A, K],
      ivStrategy: IvGen[F, A]
  ): F[(CipherText[A], AuthTag[A])] =
    ivStrategy.genIv.flatMap(encryptDetached[F](plainText, key, _))

  final def encryptDetached[F[_]](plainText: PlainText, key: K[A], ivs: IvGen[F, A])(
      implicit E: AuthEncryptor[F, A, K],
      F: Monad[F]
  ): F[(CipherText[A], AuthTag[A])] = encryptDetached[F](plainText, key)(F, E, ivs)

  final def encryptDetached[F[_]](plainText: PlainText, key: K[A], iv: Iv[A])(
      implicit E: AuthEncryptor[F, A, K]
  ): F[(CipherText[A], AuthTag[A])] = E.encryptDetached(plainText, key, iv)

  final def decryptDetached[F[_]](cipherText: CipherText[A], key: K[A], authTag: AuthTag[A])(
      implicit E: AuthEncryptor[F, A, K]
  ): F[PlainText] = E.decryptDetached(cipherText, key, authTag)

}

/** Our AEAD algebra **/
trait AEADAPI[A, K[_]] extends AuthCipherAPI[A, K] {

  final def encryptWithAAD[F[_]: Monad](plainText: PlainText, key: K[A], aad: AAD)(
      implicit E: AADEncryptor[F, A, K],
      ivStrategy: IvGen[F, A]
  ): F[CipherText[A]] =
    ivStrategy.genIv.flatMap(encryptWithAAD[F](plainText, key, _, aad))

  final def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], ivs: IvGen[F, A], aad: AAD)(
      implicit E: AADEncryptor[F, A, K],
      F: Monad[F]
  ): F[CipherText[A]] = encryptWithAAD[F](plainText, key, aad)(F, E, ivs)

  final def encryptWithAAD[F[_]](plainText: PlainText, key: K[A], iv: Iv[A], aad: AAD)(
      implicit E: AADEncryptor[F, A, K]
  ): F[CipherText[A]] = E.encryptWithAAD(plainText, key, iv, aad)

  final def encryptWithAADDetached[F[_]: Monad](plainText: PlainText, key: K[A], aad: AAD)(
      implicit E: AADEncryptor[F, A, K],
      ivStrategy: IvGen[F, A]
  ): F[(CipherText[A], AuthTag[A])] =
    ivStrategy.genIv.flatMap(encryptWithAADDetached[F](plainText, key, _, aad))

  final def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], ivs: IvGen[F, A], aad: AAD)(
      implicit E: AADEncryptor[F, A, K],
      F: Monad[F]
  ): F[(CipherText[A], AuthTag[A])] = encryptWithAADDetached[F](plainText, key, aad)(F, E, ivs)

  final def encryptWithAADDetached[F[_]](plainText: PlainText, key: K[A], iv: Iv[A], aad: AAD)(
      implicit E: AADEncryptor[F, A, K]
  ): F[(CipherText[A], AuthTag[A])] = E.encryptWithAADDetached(plainText, key, iv, aad)

  final def decryptWithAAD[F[_]](cipherText: CipherText[A], key: K[A], aad: AAD)(
      implicit E: AADEncryptor[F, A, K]
  ): F[PlainText] = E.decryptWithAAD(cipherText, key, aad)

  final def decryptWithAADDetached[F[_]](cipherText: CipherText[A], key: K[A], aad: AAD, authTag: AuthTag[A])(
      implicit E: AADEncryptor[F, A, K]
  ): F[PlainText] = E.decryptWithAADDetached(cipherText, key, aad, authTag)

}
