package tsec.authentication

import tsec.common.TSecError

package object credentials {

  case class CredentialsError(cause: String) extends TSecError

}
