import javacard.framework.*;

public class SecureApplet extends Applet {

    private OwnerPIN pin;

    // CLA byte in the command APDU
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // Instruction byte for VERIFY command
    final static byte INS_VERIFY = (byte) 0x20;

    // Instruction byte for CHANGE PIN command
    final static byte INS_CHANGE_PIN = (byte) 0x30;

    // Maximum number of tries for PIN
    final static byte PIN_TRY_LIMIT = (byte) 0x03;

    // Maximum length of PIN
    final static byte MAX_PIN_SIZE = (byte) 0x04;

    // PIN
    private final byte[] pinCode = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};

    private SecureApplet() {
        // Initialize PIN with the maximum number of tries
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(pinCode, (short) 0, (byte) pinCode.length);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SecureApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        if (buffer[ISO7816.OFFSET_CLA] != CLA_SIMPLEAPPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_VERIFY:
                verifyPin(apdu);
                break;
            case INS_CHANGE_PIN:
                changePin(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void verifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, pinLength) == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void changePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        pin.update(buffer, ISO7816.OFFSET_CDATA, pinLength);
    }
}
