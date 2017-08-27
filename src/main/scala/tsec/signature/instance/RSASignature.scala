package tsec.signature.instance

import tsec.signature.core.SignatureAlgorithm

abstract class GeneralSignature[A](signature: String){
  implicit val sig = new SignatureAlgorithm[A] {
    override lazy val algorithm: String = signature
  }
}

abstract class RSASignature[A](signature: String){
  implicit val sig = new SignatureAlgorithm[A] {
    override lazy val algorithm: String = signature
  }

  implicit val kt = new KFTag[A] {
    val keyTransformerAlgorithm: String = "RSA"
  }
}

abstract class ECDSASignature[A](signature: String, dCurve: String, outLen: Int){
  implicit val sig = new SignatureAlgorithm[A] {
    override lazy val algorithm: String = signature
  }

  implicit val curve = new ECCurve[A] {
    protected val defaultCurve: String = dCurve
  }

  implicit val kt = new ECKFTag[A] {
    val keyTransformerAlgorithm: String = "ECDSA"
    val outputLen: Int = outLen
  }

}