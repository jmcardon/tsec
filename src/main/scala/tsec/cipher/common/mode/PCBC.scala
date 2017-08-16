package tsec.cipher.common.mode

sealed trait PCBC
object PCBC extends DefaultModeKeySpec[PCBC]("PCBC")
