package tsec.cipher.common.mode

sealed trait CBC
object CBC extends DefaultModeKeySpec[CBC]("CBC")
