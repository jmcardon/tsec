package tsec.cipher.asymmetric.instances

import java.security.{PrivateKey, PublicKey}

import tsec.cipher.asymmetric.core.{AsymmetricAlgorithm, AsymmetricKeyGenerator}


abstract class WithAsymmetricGenerator[T](str: String, keySize: Int) {
  implicit val tag: AsymmetricAlgorithm[T] = AsymmetricAlgorithm[T](str, keySize)
  implicit val keyGen: AsymmetricKeyGenerator[T, PrivateKey, PublicKey] = JAsymmetricKeyGenerator.fromType[T](tag)

}
