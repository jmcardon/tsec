package tsec.cipher.instances.mode

sealed trait PCBC
object PCBC extends WithModeTag[PCBC]("PCBC") with DefaultModeKeySpec[PCBC]
