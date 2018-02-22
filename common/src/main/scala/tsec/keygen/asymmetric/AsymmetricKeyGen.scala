package tsec.keygen.asymmetric

import cats.effect.Sync

trait AsymmetricKeyGen[Alg, PrivK[_], PubK[_], KP[_], S] {

  final def generateKeyPair[F[_]](implicit F: Sync[F], S: S): F[KP[Alg]] =
    F.delay(unsafeGenerateKeyPair)

  def unsafeGenerateKeyPair(implicit S: S): KP[Alg]

  final def buildPrivateKey[F[_]](rawPk: Array[Byte])(implicit F: Sync[F], S: S): F[PrivK[Alg]] =
    F.delay(unsafeBuildPrivateKey(rawPk))

  def unsafeBuildPrivateKey(rawPk: Array[Byte])(implicit S: S): PrivK[Alg]

  final def buildPublicKey[F[_]](rawPk: Array[Byte])(implicit F: Sync[F], S: S): F[PrivK[Alg]] =
    F.delay(unsafeBuildPublicKey(rawPk))

  def unsafeBuildPublicKey(rawPk: Array[Byte])(implicit S: S): PrivK[Alg]

}
