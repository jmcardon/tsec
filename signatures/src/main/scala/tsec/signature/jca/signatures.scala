package tsec.signature.jca

sealed trait MD2withRSA

object MD2withRSA extends GeneralSignature[MD2withRSA]("MD2withRSA", "RSA")

sealed trait MD5withRSA

object MD5withRSA extends GeneralSignature[MD5withRSA]("MD5withRSA", "RSA")

sealed trait SHA1withRSA

object SHA1withRSA extends GeneralSignature[SHA1withRSA]("SHA1withRSA", "RSA")

sealed trait SHA224withRSA

object SHA224withRSA extends GeneralSignature[SHA224withRSA]("SHA224withRSA", "RSA")

sealed trait SHA256withRSA

object SHA256withRSA extends RSASignature[SHA256withRSA]("SHA256withRSA")

sealed trait SHA384withRSA

object SHA384withRSA extends RSASignature[SHA384withRSA]("SHA384withRSA")

sealed trait SHA512withRSA

object SHA512withRSA extends RSASignature[SHA512withRSA]("SHA512withRSA")

sealed trait SHA1withDSA

object SHA1withDSA extends GeneralSignature[SHA1withDSA]("SHA1withDSA", "DSA")

sealed trait SHA224withDSA

object SHA224withDSA extends GeneralSignature[SHA224withDSA]("SHA224withDSA", "DSA")

sealed trait SHA256withDSA

object SHA256withDSA extends GeneralSignature[SHA256withDSA]("SHA256withDSA", "DSA")

sealed trait NONEwithECDSA

object NONEwithECDSA extends GeneralSignature[NONEwithECDSA]("NONEwithECDSA", "ECDSA")

sealed trait SHA1withECDSA

object SHA1withECDSA extends GeneralSignature[SHA1withECDSA]("SHA1withECDSA", "ECDSA")

sealed trait SHA224withECDSA

object SHA224withECDSA extends GeneralSignature[SHA224withECDSA]("SHA224withECDSA", "ECDSA")

sealed trait SHA256withECDSA

object SHA256withECDSA extends ECDSASignature[SHA256withECDSA]("SHA256withECDSA", "P-256", 64)

sealed trait SHA384withECDSA

object SHA384withECDSA extends ECDSASignature[SHA384withECDSA]("SHA384withECDSA", "P-384", 96)

sealed trait SHA512withECDSA

object SHA512withECDSA extends ECDSASignature[SHA512withECDSA]("SHA512withECDSA", "P-521", 132)
/** End sig types */
