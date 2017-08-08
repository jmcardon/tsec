package fucc.symmetric

import javax.crypto.{KeyGenerator => KG, SecretKey}

import fucc.core.CryptoTag


object JKeyGenerator {

  def fromType[T: CryptoTag]() = new KeyGenerator[T] {

    val tag: CryptoTag[T] = implicitly[CryptoTag[T]]

    def generator =
      KG.getInstance(tag.algorithm)
    override def generateKey(): SecretKey = generator.generateKey()
  }
}
