package tsec.keygen.symmetric

private[tsec] trait SymmetricKeyGenAPI[Alg, K[_]] {

  def generateKey[F[_]](implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.generateKey

  def unsafeGenerateKey(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.generateKey

  def buildKey[F[_]](rawKey: Array[Byte])(implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.build(rawKey)

  def unsafeBuildKey(rawKey: Array[Byte])(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.build(rawKey)

}
