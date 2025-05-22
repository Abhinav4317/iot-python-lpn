from reedsolo import RSCodec
BYTES = 512//8           # 64 data bytes
T     = 32               # correct up to 32 bytes errors
NSYM  = 2*T              # 64 parity bytes
rsc   = RSCodec(nsym=NSYM)