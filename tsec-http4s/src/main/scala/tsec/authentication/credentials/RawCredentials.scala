package tsec.authentication.credentials

final case class RawCredentials[+U](identity: U, rawPassword: String)
