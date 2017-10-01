package tsec.signature.instance

import java.security.spec.{ECGenParameterSpec, PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, KeyPairGenerator}
import cats.syntax.either._

import tsec.signature.core.SigAlgoTag

abstract class GeneralSignature[A](signature: String) {
  implicit val sig = new SigAlgoTag[A] {
    override lazy val algorithm: String = signature
  }
}

abstract class RSASignature[A](signature: String) {
  implicit val sig = new SigAlgoTag[A] {
    override lazy val algorithm: String = signature
  }

  implicit val kt = new KFTag[A] {
    val keyFactoryAlgo: String = "RSA"
  }

  def generateKeyPair: SigKeyPair[A] =
    SigKeyPair.fromKeyPair[A](KeyPairGenerator.getInstance(kt.keyFactoryAlgo).generateKeyPair())

  def buildPrivateKey(keyBytes: Array[Byte]): SigPrivateKey[A] =
    SigPrivateKey.fromKey[A](
      KeyFactory.getInstance(kt.keyFactoryAlgo).generatePrivate(new PKCS8EncodedKeySpec(keyBytes))
    )

  def buildPublicKey(keyBytes: Array[Byte]): SigPublicKey[A] =
    SigPublicKey.fromKey[A](KeyFactory.getInstance(kt.keyFactoryAlgo).generatePublic(new X509EncodedKeySpec(keyBytes)))
}

abstract class ECDSASignature[A](signature: String, dCurve: String, outLen: Int)
    extends SigAlgoTag[A]
    with ECCurve[A]
    with ECKFTag[A] {

  override lazy val algorithm: String = signature

  protected val defaultCurve: String = dCurve

  val keyFactoryAlgo: String = "ECDSA"
  val outputLen: Int         = outLen

  implicit val sig: SigAlgoTag[A] = this

  implicit val curve: ECCurve[A] = this

  implicit val kt: ECKFTag[A] = this

  def generateKeyPair: SigKeyPair[A] = {
    val instance = KeyPairGenerator.getInstance(keyFactoryAlgo, ECDSASignature.Provider)
    instance.initialize(new ECGenParameterSpec(defaultCurve))
    SigKeyPair.fromKeyPair[A](instance.generateKeyPair())
  }

  def buildPrivateKey(keyBytes: Array[Byte]): SigPrivateKey[A] =
    SigPrivateKey.fromKey[A](
      KeyFactory
        .getInstance(kt.keyFactoryAlgo, ECDSASignature.Provider)
        .generatePrivate(new PKCS8EncodedKeySpec(keyBytes))
    )

  def buildPublicKey(keyBytes: Array[Byte]): SigPublicKey[A] =
    SigPublicKey.fromKey[A](
      KeyFactory
        .getInstance(kt.keyFactoryAlgo, ECDSASignature.Provider)
        .generatePublic(new X509EncodedKeySpec(keyBytes))
    )

}

object ECDSASignature {
  val Provider = "BC"
}
