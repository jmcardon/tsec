package tsec.hashing.bouncy

sealed trait Keccak224

object Keccak224 extends AsBouncyCryptoHash[Keccak224]("SHA3-224")

sealed trait Keccak256

object Keccak256 extends AsBouncyCryptoHash[Keccak256]("SHA3-256")

sealed trait Keccak384

object Keccak384 extends AsBouncyCryptoHash[Keccak384]("SHA3-384")

sealed trait Keccak512

object Keccak512 extends AsBouncyCryptoHash[Keccak512]("SHA3-512")

sealed trait Whirlpool

object Whirlpool extends AsBouncyCryptoHash[Whirlpool]("Whirlpool")

sealed trait RipeMD128

object RipeMD128 extends AsBouncyCryptoHash[RipeMD128]("RipeMD128")

sealed trait RipeMD160

object RipeMD160 extends AsBouncyCryptoHash[RipeMD160]("RipeMD160")

sealed trait RipeMD256

object RipeMD256 extends AsBouncyCryptoHash[RipeMD256]("RipeMD256")

sealed trait RipeMD320

object RipeMD320 extends AsBouncyCryptoHash[RipeMD320]("RipeMD320")
