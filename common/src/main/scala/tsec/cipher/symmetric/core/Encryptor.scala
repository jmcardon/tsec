package tsec.cipher.symmetric.core

import cats.Monad

trait Encryptor[F[_], A, K[_]] {

  final def encrypt(plainText: PlainText, key: K[A])(
      implicit ivStrategy: IvGen[F, A],
      F: Monad[F]
  ): F[CipherText[A]] =
    F.flatMap(ivStrategy.genIv)(encrypt(plainText, key, _))

  def encrypt(plainText: PlainText, key: K[A], iv: Iv[A]): F[CipherText[A]]

  def decrypt(cipherText: CipherText[A], key: K[A]): F[PlainText]

}

trait AuthEncryptor[F[_], A, K[_]] extends Encryptor[F, A, K] {
  def encryptDetached(plainText: PlainText, key: K[A])(
      implicit ivStrategy: IvGen[F, A],
      F: Monad[F]
  ): F[(CipherText[A], AuthTag[A])] =
    F.flatMap(ivStrategy.genIv)(encryptDetached(plainText, key, _))

  def encryptDetached(plainText: PlainText, key: K[A], iv: Iv[A]): F[(CipherText[A], AuthTag[A])]

  def decryptDetached(cipherText: CipherText[A], key: K[A], authTag: AuthTag[A]): F[PlainText]

}

trait AADEncryptor[F[_], A, K[_]] extends AuthEncryptor[F, A, K] {

  def encryptWithAAD(plainText: PlainText, key: K[A], aad: AAD)(
      implicit ivStrategy: IvGen[F, A],
      F: Monad[F]
  ): F[CipherText[A]] =
    F.flatMap(ivStrategy.genIv)(encryptWithAAD(plainText, key, _, aad))

  def encryptWithAAD(plainText: PlainText, key: K[A], iv: Iv[A], aad: AAD): F[CipherText[A]]

  def encryptWithAADDetached(plainText: PlainText, key: K[A], aad: AAD)(
      implicit ivStrategy: IvGen[F, A],
      F: Monad[F]
  ): F[(CipherText[A], AuthTag[A])] =
    F.flatMap(ivStrategy.genIv)(encryptWithAADDetached(plainText, key, _, aad))

  def encryptWithAADDetached(plainText: PlainText, key: K[A], iv: Iv[A], aad: AAD): F[(CipherText[A], AuthTag[A])]

  def decryptWithAAD(cipherText: CipherText[A], key: K[A], aad: AAD): F[PlainText]

  def decryptWithAADDetached(cipherText: CipherText[A], key: K[A], aad: AAD, authTag: AuthTag[A]): F[PlainText]

}
