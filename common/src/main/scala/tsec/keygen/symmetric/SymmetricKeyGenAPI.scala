package tsec.keygen.symmetric

private[tsec] trait SymmetricKeyGenAPI[Alg, K[_]] {

  @deprecated("use generateKey", "0.0.1-M10")
  def generateLift[F[_]](implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] = generateKey[F]

  def generateKey[F[_]](implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.generateKey

  @deprecated("use unsafeGenerateKey", "0.0.1-M10")
  def generateKeyUnsafe(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.generateKey

  def unsafeGenerateKey(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.generateKey

  def buildKey[F[_]](rawKey: Array[Byte])(implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.build(rawKey)

  @deprecated("use build", "0.0.1-M10")
  def buildAndLift[F[_]](rawKey: Array[Byte])(implicit S: SymmetricKeyGen[F, Alg, K]): F[K[Alg]] =
    S.build(rawKey)

  def unsafeBuildKey(rawKey: Array[Byte])(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.build(rawKey)

  @deprecated("use unsafeBuild", "0.0.1-M10")
  def buildKeyUnsafe(rawKey: Array[Byte])(implicit S: IdKeyGen[Alg, K]): K[Alg] =
    S.build(rawKey)

}
