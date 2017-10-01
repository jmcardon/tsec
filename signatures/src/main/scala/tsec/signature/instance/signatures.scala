package tsec.signature.instance

import java.security.KeyPairGenerator

case class MD2withRSA(content: Array[Byte])

object MD2withRSA extends GeneralSignature[MD2withRSA]("MD2withRSA", "RSA")

case class MD5withRSA(content: Array[Byte])

object MD5withRSA extends GeneralSignature[MD5withRSA]("MD5withRSA", "RSA")

case class SHA1withRSA(content: Array[Byte])

object SHA1withRSA extends GeneralSignature[SHA1withRSA]("SHA1withRSA", "RSA")

case class SHA224withRSA(content: Array[Byte])

object SHA224withRSA extends GeneralSignature[SHA224withRSA]("SHA224withRSA", "RSA")

case class SHA256withRSA(content: Array[Byte])

object SHA256withRSA extends RSASignature[SHA256withRSA]("SHA256withRSA")

case class SHA384withRSA(content: Array[Byte])

object SHA384withRSA extends RSASignature[SHA384withRSA]("SHA384withRSA")

case class SHA512withRSA(content: Array[Byte])

object SHA512withRSA extends RSASignature[SHA512withRSA]("SHA512withRSA")

case class SHA1withDSA(content: Array[Byte])

object SHA1withDSA extends GeneralSignature[SHA1withDSA]("SHA1withDSA", "DSA")

case class SHA224withDSA(content: Array[Byte])

object SHA224withDSA extends GeneralSignature[SHA224withDSA]("SHA224withDSA", "DSA")

case class SHA256withDSA(content: Array[Byte])

object SHA256withDSA extends GeneralSignature[SHA256withDSA]("SHA256withDSA", "DSA")

case class NONEwithECDSA(content: Array[Byte])

object NONEwithECDSA extends GeneralSignature[NONEwithECDSA]("NONEwithECDSA", "ECDSA") {
  override def generateKeyPairUnsafe: SigKeyPair[NONEwithECDSA] =
    SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
}

case class SHA1withECDSA(content: Array[Byte])

object SHA1withECDSA extends GeneralSignature[SHA1withECDSA]("SHA1withECDSA", "ECDSA") {
  override def generateKeyPairUnsafe: SigKeyPair[SHA1withECDSA] =
    SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
}

case class SHA224withECDSA(content: Array[Byte])

object SHA224withECDSA extends GeneralSignature[SHA224withECDSA]("SHA224withECDSA", "ECDSA") {
  override def generateKeyPairUnsafe: SigKeyPair[SHA224withECDSA] =
    SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
}

case class SHA256withECDSA(content: Array[Byte])

object SHA256withECDSA extends ECDSASignature[SHA256withECDSA]("SHA256withECDSA", "P-256", 64)

case class SHA384withECDSA(content: Array[Byte])

object SHA384withECDSA extends ECDSASignature[SHA384withECDSA]("SHA384withECDSA", "P-384", 96)

case class SHA512withECDSA(content: Array[Byte])

object SHA512withECDSA extends ECDSASignature[SHA512withECDSA]("SHA512withECDSA", "P-521", 132)
