package tsec.signature.instance

trait KFTag[A] {
  val keyTransformerAlgorithm: String
}

trait ECKFTag[A] extends KFTag[A] {
  val outputLen: Int
}
