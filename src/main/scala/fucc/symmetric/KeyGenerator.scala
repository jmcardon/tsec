package fucc.symmetric


trait KeyGenerator[T] {
  def generateKey(): SecretKey[T]
}



