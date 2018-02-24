package tsec.keygen.symmetric

trait SymmKeyGenAPI[Alg, K[_]] {

  @deprecated("0.0.1-M10", "use generateKey")
  def generateLift[F[_]](implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] = generateKey[F]

  def generateKey[F[_]](implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.generateKey

  @deprecated("0.0.1-M10", "use unsafeGenerateKey")
  def generateKeyUnsafe(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.generateKey

  def unsafeGenerateKey(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.generateKey

  def buildKey[F[_]](rawKey: Array[Byte])(implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.build(rawKey)

  def unsafeBuildKey(rawKey: Array[Byte])(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.build(rawKey)

  @deprecated("0.0.1-M10", "use unsafeBuild")
  def buildKeyUnsafe(rawKey: Array[Byte])(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.build(rawKey)

}
