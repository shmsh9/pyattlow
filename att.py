from enum import Enum

ATT_CID = 4

class ATT_HDR_OPCODE(Enum):
    ATT_ERROR_RSP                 = 0x01
    ATT_EXCHANGE_MTU_REQ          = 0x02
    ATT_EXCHANGE_MTU_RSP          = 0x03
    ATT_FIND_INFORMATION_REQ      = 0x04
    ATT_FIND_INFORMATION_RSP      = 0x05
    ATT_FIND_BY_TYPE_VALUE_REQ    = 0x06
    ATT_FIND_BY_TYPE_VALUE_RSP    = 0x07
    ATT_READ_BY_TYPE_REQ          = 0x08
    ATT_READ_BY_TYPE_RSP          = 0x09
    ATT_READ_REQ                  = 0x0a
    ATT_READ_RSP                  = 0x0b
    ATT_READ_BLOB_REQ             = 0x0c
    ATT_READ_BLOB_RSP             = 0x0d
    ATT_READ_MULTIPLE_REQ         = 0x0e
    ATT_READ_MULTIPLE_RSP         = 0x0f
    ATT_READ_BY_GROUP_TYPE_REQ    = 0x10
    ATT_READ_BY_GROUP_TYPE_RSP    = 0x11
    ATT_WRITE_REQ                 = 0x12
    ATT_WRITE_RSP                 = 0x13
    ATT_WRITE_CMD                 = 0x52
    ATT_PREPARE_WRITE_REQ         = 0x16
    ATT_PREPARE_WRITE_RSP         = 0x17
    ATT_EXECUTE_WRITE_REQ         = 0x18
    ATT_EXECUTE_WRITE_RSP         = 0x19
    ATT_HANDLE_VALUE_NTF          = 0x1b
    ATT_HANDLE_VALUE_IND          = 0x1d
    ATT_HANDLE_VALUE_CFM          = 0x1e
    ATT_READ_MUTIPLE_VARIABLE_REQ = 0x20
    ATT_READ_MUTIPLE_VARIABLE_RSP = 0x21
    ATT_MUTIPLE_HANDLE_VALUE_NTF  = 0x22
    ATT_SIGNED_WRITE_COMMAND      = 0xd2

class ATT_ERRCODE(Enum):
    ATT_ERRCODE_INVALID_HANDLE                   = 0x01
    ATT_ERRCODE_READ_NOT_PERMITTED               = 0x02
    ATT_ERRCODE_WRITE_NOT_PERMITTED              = 0x03
    ATT_ERRCODE_INVALID_PDU                      = 0x04
    ATT_ERRCODE_INSUFFICIENT_AUTHENTICATION      = 0x05
    ATT_ERRCODE_REQUEST_NOT_SUPPORT              = 0x06
    ATT_ERRCODE_INVALID_OFFSET                   = 0x07
    ATT_ERRCODE_INSUFFICIENT_AUTHORIZATION       = 0x08
    ATT_ERRCODE_PREPARE_QUEUE_FULL               = 0x09
    ATT_ERRCODE_ATTRIBUTE_NOT_FOUND              = 0x0a
    ATT_ERRCODE_ATTRIBUTE_NOT_LONG               = 0x0b
    ATT_ERRCODE_INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0c
    ATT_ERRCODE_INVALID_ATTRIBUTE_VALUE_LENGTH   = 0x0d
    ATT_ERRCODE_UNLIKELY_ERROR                   = 0x0e
    ATT_ERRCODE_INSUFFICIENT_ENCRYPTION          = 0x0f
    ATT_ERRCODE_UNSUPPORTED_GROUP_TYPE           = 0x10
    ATT_ERRCODE_INSUFFICIENT_RESOURCE            = 0x11
    ATT_ERRCODE_DATABASE_OUT_OF_SYNC             = 0x12
    ATT_ERRCODE_VALUE_NOT_ALLOW                  = 0x13
    ATT_ERRCODE_APPLICATION_ERROR                = 0x80

class AttPDU():
    _buff = None
    opcode = None
    param = None
    
    def __init__(self, buff):
        self._buff = buff
        self.opcode = self._buff[0]
        self.param = self._buff[1::]
    
    def __str__(self):
        return str(vars(self))
    
    def raw(self):
        return [int(x) for x in self._buff]

class AttErrResp(AttPDU):
    err_opcode = None
    err_handle = None
    err_code = None
    def __init__(self, buff):
        super().__init__(buff)
        if self.opcode != ATT_HDR_OPCODE.ATT_ERROR_RSP.value:
            raise Exception(f"invalid opcode for ATT_ERROR_RSP {self.opcode}")
        self.err_opcode = self.param[0]
        self.err_handle = (self.param[1] << 8 | self.param[2])
        self.err_code = self.param[3]

class AttReadResp(AttPDU):
    def __init__(self, buff):
        super().__init__(buff)
        if self.opcode != ATT_HDR_OPCODE.ATT_READ_RSP.value:
            raise Exception(f"invalid opcode for ATT_READ_RSP {self.opcode}")

class AttReadReq(AttPDU):
    _buff = None
    handle = None
    def __init__(self, handle):
        if handle > 0xffff:
            raise Exception(f"handle too big {handle}")
        self.handle = handle
        self._buff = [
            ATT_HDR_OPCODE.ATT_READ_REQ.value,
            (handle >> 8) & 0xff,
            (handle & 0xff)
        ]
        super().__init__(self._buff)

class AttWriteReq(AttPDU):
    _buff = None
    handle = None
    request = None
    def __init__(self, handle, request):
        if handle > 0xffff:
            raise Exception(f"handle too big {handle}")
        self.handle = handle
        self._buff = [
            ATT_HDR_OPCODE.ATT_WRITE_REQ.value,
            (handle >> 8) & 0xff,
            (handle & 0xff)
        ]
        self.request = request
        self._buff.extend([(int(x) & 0xff) for x in request])
        super().__init__(self._buff)

class AttEnableNotif(AttWriteReq):
    def __init__(self, handle):
        super().__init__(handle, [0x01, 0x00])

