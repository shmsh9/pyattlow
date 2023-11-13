import asyncio
from att import AttClient

DST = "60:8A:10:5C:40:9C"

def notif_callback(data):

    print(f"notif_callback : {''.join([chr(x) for x in data])}")

async def main():
    client = AttClient(DST)
    await asyncio.sleep(3)

    await client.notify(0x0037, notif_callback)

    await client.write(0x003a, [0x70, 0x61, 0x72, 0x6b, 0x78, 0x39, 0xd])       #FW info
    """
    await client.write(0x003a, [0x70, 0x61, 0x72, 0x6b, 0x77, 0x31, 0x33, 0x0d]) #T2
    await asyncio.sleep(3)
    await client.write(0x003a, [0x70, 0x61, 0x72, 0x6b, 0x77, 0x31, 0x31, 0x0d]) #Backward
    await asyncio.sleep(3)
    await client.write(0x003a, [0x70, 0x61, 0x72, 0x6b, 0x77, 0x31, 0x31, 0x0d]) #Backward
    await asyncio.sleep(5)
    """

asyncio.run(main())

