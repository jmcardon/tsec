package tsec.cipher.instances.mode

sealed trait PCBC
object PCBC extends DefaultModeKeySpec[PCBC]("PCBC")
