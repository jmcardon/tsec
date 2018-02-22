package tsec.keygen.symmetric

import cats.effect.Sync

trait SymmetricKeyGen[Alg, K[_], S] {

  def generateKey[F[_]](implicit F: Sync[F], S: S): F[K[Alg]] =
    F.delay(unsafeGenerate)

  def unsafeGenerate(implicit S: S): K[Alg]

  def build[F[_]](rawKey: Array[Byte])(implicit F: Sync[F], S: S): F[K[Alg]] =
    F.delay(unsafeBuild(rawKey))

  def unsafeBuild(rawKey: Array[Byte])(implicit S: S): K[Alg]

}