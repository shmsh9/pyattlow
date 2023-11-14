from enum import Enum
import l2capsocket
import asyncio

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
    
    def values():
        return [x.value for x in ATT_HDR_OPCODE]

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

    def values():
        return [x.value for x in ATT_HDR_OPCODE]


class AttPDU():
    _buff = None
    opcode = None
    param = None
    
    def __init__(self, buff):
        self._buff = buff
        self.opcode = self._buff[0]
        if self.opcode not in ATT_HDR_OPCODE.values():
            raise Exception(f"invalid opcode {self.opcode} for AttPDU")
        self.param = self._buff[1::]
    
    def __str__(self):
        return str(vars(self))
    
    def raw(self):
        return [(int(x) & 0xff) for x in self._buff]

class AttErrResp(AttPDU):
    error_opcode = None
    err_handle = None
    error_code = None
    def __init__(self, buff):
        super().__init__(buff)
        if self.opcode != ATT_HDR_OPCODE.ATT_ERROR_RSP.value:
            raise Exception(f"invalid opcode for ATT_ERROR_RSP {self.opcode}")
        self.error_opcode = self.param[0]
        if self.error_opcode not in ATT_HDR_OPCODE.values():
            raise Exception(f"invalid error opcode {self.error_opcode}")

        self.err_handle = (self.param[2] << 8 | self.param[1] & 0xff) & 0xffff
        self.error_code = self.param[3]
        if self.error_code not in ATT_ERRCODE.values():
            raise Exception(f"invalid error code {self.error_code}")


class AttReadResp(AttPDU):
    handle = None
    def __init__(self, buff):
        super().__init__(buff)
        if self.opcode != ATT_HDR_OPCODE.ATT_READ_RSP.value:
            raise Exception(f"invalid opcode for ATT_READ_RSP {self.opcode}")
        self.handle = self.param[0]

class AttReadReq(AttPDU):
    _buff = None
    handle = None
    def __init__(self, handle):
        if handle > 0xffff:
            raise Exception(f"handle too big {handle}")
        self.handle = handle
        self._buff = [
            ATT_HDR_OPCODE.ATT_READ_REQ.value,
            (handle & 0xff),
            (handle >> 8) & 0xff
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
            (handle & 0xff),
            (handle >> 8) & 0xff
        ]
        self.request = request
        self._buff.extend([(int(x) & 0xff) for x in request])
        super().__init__(self._buff)

class AttFindByTypeValueReq(AttPDU):
    def __init__(self, buff):
        super().__init__(buff)
        if self.opcode != ATT_HDR_OPCODE.ATT_FIND_BY_TYPE_VALUE_REQ.value:
            raise Exception(f"invalid opcode for ATT_FIND_BY_TYPE_VALUE_REQ {self.opcode}")
        self.start_handle = ( (self.param[1] << 8) | self.param[0] & 0xff ) & 0xffff
        self.end_handle = ( (self.param[3] << 8) | self.param[2] & 0xff ) & 0xffff
        self.uuid = ( (self.param[5] << 8) | self.param[4] & 0xff ) & 0xffff
        self.value = self.param[6::]

class AttHandleValueNotif(AttPDU):
    def __init__(self, buff):
        super().__init__(buff)
        if self.opcode != ATT_HDR_OPCODE.ATT_HANDLE_VALUE_NTF.value:
            raise Exception(f"invalid opcode for ATT_HANDLE_VALUE_NTF {self.opcode}")
        self.handle = ( (self.param[1] << 8) | self.param[0] & 0xff ) & 0xffff
        self.data = self.param[2::]

class AttClient():
    _sock = None
    _resp_read = {}
    _write_has_responded = None
    _notif_callbacks = {}
    def __init__(self, mac):
        self._write_has_responded = asyncio.Event()
        self._sock = l2capsocket.l2capsocket()
        self._sock.bind(("00:00:00:00:00:00", ATT_CID))
        self._sock.connect((mac, ATT_CID))
        loop = asyncio.get_event_loop()
        loop.add_reader(self._sock._sock, self._read_callback)
        
    async def notify(self, handle, cb):
        await self.write(handle+1, [0x01, 0x00])
        self._notif_callbacks[handle] = cb

    async def write(self, handle, request):
        r = AttWriteReq(handle, request)
        self._sock.write(
            r.raw()
        )
        await self._write_has_responded.wait()
        #while not self._write_has_responded:
        #    await asyncio.sleep(0.1)

    async def read(self, handle, timeout=1):
        self._sock.write(
            AttReadReq(handle).raw()
        )
        i = 0
        while not self._resp_read.get(handle):
            await asyncio.sleep(1)
            i += 1
            if i == timeout:
                raise Exception(f"timeout for read on handle {handle}")
        r = self._resp_read[handle]
        self._resp_read[handle] = None
        return r

    def _read_callback(self):
        r = AttPDU(self._sock.read())
        
        if r.opcode == ATT_HDR_OPCODE.ATT_HANDLE_VALUE_NTF.value:
            r = AttHandleValueNotif(r._buff)
            r.handle = (r.param[1] << 8 | r.param[0] & 0xff) & 0xffff
            if not self._notif_callbacks.get(r.handle):
                print(f"unhandled notification : {r}")
            else:
                self._notif_callbacks[r.handle](r.data)
            return
        
        if r.opcode == ATT_HDR_OPCODE.ATT_READ_RSP.value:
            r = AttReadResp(r._buff)
            if self._resp_read.get(r.handle):
                self._resp_read[r.handle].append(r)
            else:
                self._resp_read[r.handle] = [r]
            pass
            return

        if r.opcode == ATT_HDR_OPCODE.ATT_WRITE_RSP.value:
            self._write_has_responded.set()
            print(f"write response : {r}")
            return

        if r.opcode == ATT_HDR_OPCODE.ATT_ERROR_RSP.value:
            r = AttErrResp(r._buff)
            print(f"received error : {r}")
            return

        if r.opcode == ATT_HDR_OPCODE.ATT_FIND_BY_TYPE_VALUE_REQ.value:
            r = AttFindByTypeValueReq(r._buff)
            resp = AttErrResp([
                ATT_HDR_OPCODE.ATT_ERROR_RSP.value,
                ATT_HDR_OPCODE.ATT_FIND_BY_TYPE_VALUE_REQ.value,
                0x00, 0x00, #handle
                ATT_ERRCODE.ATT_ERRCODE_REQUEST_NOT_SUPPORT.value
            ])
            print(f"received ATT_FIND_BY_TYPE_VALUE_REQ : {r}\nresponding feature not supported: {resp}")
            self._sock.write(resp.raw())
            """
            resp = [
                ATT_HDR_OPCODE.ATT_READ_BY_TYPE_REQ.value,
                0x37, 0x00, #starting handle
                0x40, 0x00, #ending handle
                0x03, 0x28  #UUID
            ]
            self._sock.write(resp)
            """
            return

        print(f"received unhandled : {r}")
