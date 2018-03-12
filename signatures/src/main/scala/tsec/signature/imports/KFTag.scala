package tsec.signature.imports

import cats.Id
import tsec.keygen.asymmetric.{AsymmetricKeyGen, AsymmetricKeyGenAPI}

/** Trait to add a tag to an algorithm used by the JCA key factor
  * this allows us to abstract over the KeyFactory instance via types
  *
  * @tparam A the signature type
  */
trait KFTag[A] extends AsymmetricKeyGenAPI[A, SigPublicKey, SigPrivateKey, SigKeyPair]{
  private[tsec] def keyFactoryAlgo: String
}

trait RSAKFTag[A] extends KFTag[A] {
  def generateKeyPairStrong[F[_]](implicit S: JCARSASigKG[F, A]): F[SigKeyPair[A]] =
    S.generateKeyPairStrong

  def unsafegenerateKeyPairStrong(implicit S: JCARSASigKG[Id, A]): SigKeyPair[A] =
    S.generateKeyPairStrong
}

/** KFTag, but for elliptic curves
  *
  * @tparam A the signature type
  */
trait ECKFTag[A] extends KFTag[A] {
  def outputLen: Int

  def buildPrivateFromPoint[F[_]](bi: BigInt)(implicit J: JCAECKG[F, A]): F[SigPrivateKey[A]] =
    J.buildPrivateKeyFromPoint(bi)

  def unsafebuildPrivateKeyFromPoint(S: BigInt)(implicit J: JCAECKG[Id, A]): SigPrivateKey[A] =
    J.buildPrivateKeyFromPoint(S)

  def buildPublicKey[F[_]](x: BigInt, y: BigInt)(
      implicit J: JCAECKG[F, A]
  ): F[SigPublicKey[A]] =
    J.buildPublicKeyFromPoints(x, y)

  def unsafeBuildPublicKeyFromPoints(x: BigInt, y: BigInt)(implicit J: JCAECKG[Id, A]): SigPublicKey[A] =
    J.buildPublicKeyFromPoints(x, y)
}

abstract class JCASigKG[F[_], A] extends AsymmetricKeyGen[F, A, SigPublicKey, SigPrivateKey, SigKeyPair]

abstract class JCARSASigKG[F[_], A] extends JCASigKG[F, A] {
  def generateKeyPairStrong: F[SigKeyPair[A]]
}

abstract class JCAECKG[F[_], A] extends JCASigKG[F, A] {
  def outputLen: Int

  def buildPrivateKeyFromPoint(S: BigInt): F[SigPrivateKey[A]]

  def buildPublicKeyFromPoints(x: BigInt, y: BigInt): F[SigPublicKey[A]]
}
