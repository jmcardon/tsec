package fucc.symmetric

import javax.crypto.{SecretKey => JSecretKey}

case class SecretKey[A](key: JSecretKey) extends AnyVal
