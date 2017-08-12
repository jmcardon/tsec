package tsec.asymmetric.instances

import tsec.cipher.core.{CipherAlgo, CipherAlgorithm}
import tsec.core.CryptoTag
import com.softwaremill.tagging._
import tsec.asymmetric.cipher.core.AsymmetricKeyGenerator

abstract class WithAsymmetricGenerator[T](repr: String) {
  implicit val tag: CipherAlgo[T] = CryptoTag.fromString[T](repr).taggedWith[CipherAlgorithm]
  implicit val keyGen: AsymmetricKeyGenerator[T] = JAsymmetricKeyGenerator.fromType[T](tag)
}
