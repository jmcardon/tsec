package tsec.signature.instance

import tsec.signature.core.SignatureAlgorithm

abstract class WithSignature[A](signature: String){
  implicit val sig = new SignatureAlgorithm[A] {
    override lazy val algorithm: String = signature
  }
}