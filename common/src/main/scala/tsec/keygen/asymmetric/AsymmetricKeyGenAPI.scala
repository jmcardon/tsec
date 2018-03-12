package tsec.keygen.asymmetric

import cats.Id

trait AsymmetricKeyGenAPI[Alg, PubK[_], PrivK[_], KP[_]] {

  final def generateKeyPair[F[_]](
      implicit S: AsymmetricKeyGen[F, Alg, PubK, PrivK, KP]
  ): F[KP[Alg]] = S.generateKeyPair

  final def unsafeGenerateKeyPair(
      implicit S: AsymmetricKeyGen[Id, Alg, PubK, PrivK, KP]
  ): KP[Alg] = S.generateKeyPair

  final def buildPrivateKey[F[_]](rawPk: Array[Byte])(
      implicit S: AsymmetricKeyGen[F, Alg, PubK, PrivK, KP]
  ): F[PrivK[Alg]] =
    S.buildPrivateKey(rawPk)

  final def unsafeBuildPrivateKey(rawPk: Array[Byte])(
      implicit S: AsymmetricKeyGen[Id, Alg, PubK, PrivK, KP]
  ): PrivK[Alg] =
    S.buildPrivateKey(rawPk)

  final def buildPublicKey[F[_]](
      rawPk: Array[Byte]
  )(implicit S: AsymmetricKeyGen[F, Alg, PubK, PrivK, KP]): F[PubK[Alg]] =
    S.buildPublicKey(rawPk)

  final def unsafeBuildPublicKey(rawPk: Array[Byte])(
      implicit S: AsymmetricKeyGen[Id, Alg, PubK, PrivK, KP]
  ): Id[PubK[Alg]] =
    S.buildPublicKey(rawPk)

}
