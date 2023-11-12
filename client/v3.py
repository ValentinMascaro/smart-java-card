from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.Exceptions import NoCardException
import hashlib
# AID of the applet
APPLET_AID = [0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01, 0x24]


# CLA of the SecureApplet
CLA_SECUREAPPLET = 0xB0

# INS codes
INS_VERIFY = 0x20
INS_CHANGE_PIN = 0x30
INS_GET_PUB_KEY = 0x40

# Helper function to connect to the card
def get_card():
    r = readers()
    if len(r) < 1:
        print("No readers available!")
        return None, None
    reader = r[0]
    print("Using reader:", reader)
    try:
        connection = reader.createConnection()
        connection.connect()
        return reader, connection
    except NoCardException:
        print("No card present!")
        return None, None

# Function to select applet using its AID
def select_applet(connection, aid):
    SELECT_APDU = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid
    data, sw1, sw2 = connection.transmit(SELECT_APDU)
    if (sw1, sw2) == (0x90, 0x00):
        print("Applet selection successful")
        return True
    else:
        print(f"Failed to select applet: SW1: {hex(sw1)}, SW2: {hex(sw2)}")
        return False

# Function to verify the PIN
def verify_pin(connection, pin):
    # CLA INS P1 P2 Lc Data
    COMMAND = [CLA_SECUREAPPLET, INS_VERIFY, 0x00, 0x00, len(pin)] + pin
    #for byte in COMMAND :
    #   print(hex(byte))
    data, sw1, sw2 = connection.transmit(COMMAND)
    #data, sw1, sw2 = connection.transmit([0xB0,0x20,0x00,0x00,0x04,0x01,0x02,0x03,0x04])
    if (sw1, sw2) == (0x90, 0x00):
        print("PIN verification successful")
        #print(f"PIN  SW1: {hex(sw1)}, SW2: {hex(sw2)}")
    else:
        print(f"PIN verification failed: SW1: {hex(sw1)}, SW2: {hex(sw2)}")

# Function to change the PIN
def change_pin(connection, new_pin):
    CHANGE_PIN_APDU = [CLA_SECUREAPPLET, INS_CHANGE_PIN, 0x00, 0x00, len(new_pin)] + new_pin
    data, sw1, sw2 = connection.transmit(CHANGE_PIN_APDU)

    if (sw1, sw2) == (0x90, 0x00):
        print("PIN change successful")
    else:
        print(f"PIN change failed: SW1: {hex(sw1)}, SW2: {hex(sw2)}")

# We utilised this function to test if we succeeded at key regeneration
def getPublicKey(connection):
    GET_KEY_APDU =[CLA_SECUREAPPLET,INS_GET_PUB_KEY,0x00,0x00,len(APPLET_AID)]+APPLET_AID
    data, sw1, sw2 = connection.transmit(GET_KEY_APDU)
    if (sw1, sw2) == (0x90, 0x00):
        print("reponse :",bytes(data))
       # print(f": SW1: {hex(sw1)}, SW2: {hex(sw2)}")
    elif sw1==0x61:
        while(sw1==0x61):
            GET_KEY_APDU =[0xA0,0xC0,0x00,0x00,sw2]
            data, sw1, sw2 = connection.transmit(GET_KEY_APDU)
            print("reponse :",bytes(data))
          #  print(f": SW1: {hex(sw1)}, SW2: {hex(sw2)}")
    else:
        print(f": SW1: {hex(sw1)}, SW2: {hex(sw2)}")

# Example usage
if __name__ == '__main__':
    reader, connection = get_card()
    if connection is not None:
        if select_applet(connection,APPLET_AID):
            while True:
                print("1. Login (Default password: 1234)")
                print("2. Changer le code PIN")
                print("3. Afficher public key")
                print("4. Quitter")

                choix=input("Choississez une option : ")
                if choix=="1":
                    code_pin_saisi = input("Entrez le code pin : ")
                    code_pin_saisi_hex=[int(digit) for digit in code_pin_saisi]
                    verify_pin(connection,code_pin_saisi_hex)
                elif choix=='2':
                    code_pin_saisi = input("Entrez le nouveau code pin : ")
                    code_pin_saisi_hex=[int(digit) for digit in code_pin_saisi]
                    change_pin(connection,code_pin_saisi_hex)
                elif choix=='4':
                    print("Au revoir")
                    break
                elif choix=='3':
                    getPublicKey(connection)
                else:
                    print("choix invalide. Banane")
                print()