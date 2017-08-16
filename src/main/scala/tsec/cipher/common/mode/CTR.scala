package tsec.cipher.common.mode

sealed trait CTR
object CTR extends DefaultModeKeySpec[CTR]("CTR")
