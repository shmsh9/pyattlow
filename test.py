import asyncio
from att import AttClient

DST = "E8:31:CD:02:0F:56"
"""
s = l2capsocket()
s.bind(("00:00:00:00:00:00", att.ATT_CID))
s.connect((DST, att.ATT_CID))

garbage = att.AttReadReq(handle=0x60)
print(garbage)
s.write(garbage.raw())
r = att.AttErrResp(s.read())
print(r)

garbage2 = att.AttEnableNotif(handle=0x60)
print(garbage2)
s.write(garbage2.raw())
r = att.AttErrResp(s.read())
print(r)

not_garbage = att.AttPDU([0x10,0x01,0x00,0xff,0xff,0x00,0x28])
print(not_garbage)
s.write(not_garbage.raw())
r = att.AttPDU(s.read())
print(r)
"""
async def main():
    client = AttClient(DST)
    while True:
        client.write(0x10, [0xaa, 0xbb])
        print(await client.read(0x10, timeout=5))
        #await asyncio.sleep(0.1)

asyncio.run(main())

