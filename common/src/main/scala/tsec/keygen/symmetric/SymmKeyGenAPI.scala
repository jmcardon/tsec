package tsec.keygen.symmetric

trait SymmKeyGenAPI[Alg, K[_]] {

  def generateKey[F[_]](implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.generateKey

  def unsafeGenerateKey(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.generateKey

  def build[F[_]](rawKey: Array[Byte])(implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.build(rawKey)

  def unsafeBuild(rawKey: Array[Byte])(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.build(rawKey)

}
