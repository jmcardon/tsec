package tsec.keygen.asymmetric

trait AsymmetricKeyGen[F[_], Alg, PubK[_], PrivK[_], KP[_]] {

  def generateKeyPair: F[KP[Alg]]

  def buildPrivateKey(rawPk: Array[Byte]): F[PrivK[Alg]]

  def buildPublicKey(rawPk: Array[Byte]): F[PubK[Alg]]

}
