package tsec.signature.core

import tsec.signature.imports._

/** Trait to add a tag to an algorithm used by the JCA key factor
  * this allows us to abstract over the KeyFactory instance via types
  *
  * @tparam A the signature type
  */
trait KFTag[A] {
  val keyFactoryAlgo: String

  def generateKeyPair: Either[SignatureKeyError, SigKeyPair[A]]

  def generateKeyPairUnsafe: SigKeyPair[A]

  def buildPrivateKey(keyBytes: Array[Byte]): Either[SignatureKeyError, SigPrivateKey[A]]

  def buildPrivateKeyUnsafe(keyBytes: Array[Byte]): SigPrivateKey[A]

  def buildPublicKey(keyBytes: Array[Byte]): Either[SignatureKeyError, SigPublicKey[A]]

  def buildPublicKeyUnsafe(keyBytes: Array[Byte]): SigPublicKey[A]
}

trait RSAKFTag[A] extends KFTag[A] {
  def generateKeyPairStrong: Either[SignatureKeyError, SigKeyPair[A]]

  def generateKeyPairStrongUnsafe: SigKeyPair[A]
}

/** KFTag, but for elliptic curves
  *
  * @tparam A the signature type
  */
trait ECKFTag[A] extends KFTag[A] {
  val outputLen: Int

  def buildPrivateKeyUnsafe(S: BigInt): SigPrivateKey[A]

  def buildPrivateKey(S: BigInt): Either[SignatureKeyError, SigPrivateKey[A]]

  def buildPublicKey(x: BigInt, y: BigInt): Either[SignatureKeyError, SigPublicKey[A]]

  def buildPublicKeyUnsafe(x: BigInt, y: BigInt): SigPublicKey[A]

}
