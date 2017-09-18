package tsec.signature.instance

/**
  * Trait to add a tag to an algorithm used by the JCA key factor
  * this allows us to abstract over the KeyFactory instance via types
  *
  * @tparam A the signature type
  */
trait KFTag[A] {
  val keyFactoryAlgo: String
}

/**
  * KFTag, but for elliptic curves
  *
  * @tparam A the signature type
  */
trait ECKFTag[A] extends KFTag[A] {
  val outputLen: Int
}
