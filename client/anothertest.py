from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.util import toHexString

for reader in readers():
    try:
        connection = reader.createConnection()
        connection.connect()
        print(reader)
    except NoCardException:
        print(reader,"ya po de carte ;-;")
        exit()
