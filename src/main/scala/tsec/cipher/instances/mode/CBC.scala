package tsec.cipher.instances.mode

sealed trait CBC
object CBC extends DefaultModeKeySpec[CBC]("CBC")
