from smartcard.System import readers
from smartcard.util import toHexString
# AIDs
APPLET_AID = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x02]
# Function to get the first available reader and card
def get_card():
    r = readers()
    if not r:
        print("No smart card readers found")
        return None, None

    reader = r[0]
    print("Using reader:", reader)

    connection = reader.createConnection()
    connection.connect()

    return reader, connection

# Function to verify PIN
def verify_pin(connection, pin):
    # The APDU command for PIN verification might look something like this:
    # This is just an example, the actual APDU command will depend on your smart card applet implementation.
    # CLA INS P1 P2 P3 Data
    COMMAND = [0x00, 0x20, 0x00, 0x00, len(pin)] + pin
    data, sw1, sw2 = connection.transmit(COMMAND)

    # The status words sw1 and sw2 are the response status from the card
    # For example, (0x90, 0x00) usually means success.
    if (sw1, sw2) == (0x90, 0x00):
        print("PIN verification successful")
    else:
        print(f"PIN verification failed: SW1: {hex(sw1)}, SW2: {hex(sw2)}")

# Example usage
def select_applet(connection, aid):
    COMMAND = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
    data, sw1, sw2 = connection.transmit(COMMAND)
    if (sw1, sw2) == (0x90, 0x00):
        print("Applet selection successful")
        return True
    else:
        print(f"Applet selection failed: SW1: {hex(sw1)}, SW2: {hex(sw2)}")
        return False

# The rest of the code remains the same as before
# ...
def get_hello_robert(connection):
    # APDU command for the custom 'Hello robert' instruction
    # CLA INS P1 P2 Le
    # Le is set to 0x0C as indicated by the card (12 bytes)
    COMMAND = [0x00, 0x40, 0x00, 0x00, 0x0C]
    data, sw1, sw2 = connection.transmit(COMMAND)
    if (sw1, sw2) == (0x90, 0x00):
        print("Response from applet:", bytes(data).decode())
    else:
        print(f"Failed to get response: SW1: {hex(sw1)}, SW2: {hex(sw2)}")

# Example usage
if __name__ == '__main__':
    reader, connection = get_card()
    if connection is not None:
        if select_applet(connection, APPLET_AID):
            get_hello_robert(connection)