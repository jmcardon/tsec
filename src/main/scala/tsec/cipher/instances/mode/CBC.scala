package tsec.cipher.instances.mode

sealed trait CBC
object CBC extends WithModeTag[CBC]("CBC") with DefaultModeKeySpec[CBC]
