package tsec.cipher.asymmetric.instances

import java.security.{PrivateKey, PublicKey}

import tsec.cipher.asymmetric.core.{AsymmetricAlgorithm, AsymmetricKeyGenerator}


abstract class WithAsymmetricGenerator[T](str: String) {
  implicit val tag: AsymmetricAlgorithm[T] = AsymmetricAlgorithm[T](str)
  implicit val keyGen: AsymmetricKeyGenerator[T, PrivateKey, PublicKey] = JAsymmetricKeyGenerator.fromType[T](tag)

}
