package fucc.cipher.instances.mode

sealed trait CBC
object CBC extends WithModeTag[CBC]("CBC")
