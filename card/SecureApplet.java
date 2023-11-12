package card;

import javacard.framework.*;
import javacard.security.*;
import java.math.BigInteger;


/*
import javacard.security.KeyPair;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
/*
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
 */
public class SecureApplet extends Applet {

    private boolean isPinSet = false;
    private OwnerPIN pin;

    private KeyPair rsaKeyPair;
    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;

    private static final byte[] ASN1_SHA256 = {
            (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x60,
            (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02,
            (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x20
    };
    // CLA byte in the command APDU
    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // Instruction byte for VERIFY command
    final static byte INS_VERIFY = (byte) 0x20;

    // Instruction byte for CHANGE PIN command
    final static byte INS_CHANGE_PIN = (byte) 0x30;

    final static byte INS_GET_PUBLIC_KEY = (byte) 0x40;

    final static byte INS_SIGN = (byte) 0x50;

    // Maximum number of tries for PIN
    final static byte PIN_TRY_LIMIT = (byte) 0x50;

    // Maximum length of PIN
    final static byte MAX_PIN_SIZE = (byte) 0x04;

    // PIN
    public static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};

    public static final short SW_PIN_FAILED_MORE = (short) 0x9704;
    /**
     * PIN failed, 2 tries remaining
     */
    public static final short SW_PIN_FAILED_2 = (short) 0x9A04;
    /**
     * PIN failed, 1 try remaining
     */
    public static final short SW_PIN_FAILED_1 = (short) 0x9904;
    /**
     * PIN failed, card blocked
     */
    public static final short SW_BLOCKED = (short) 0x6983;
    static final byte PIN_LENGTH = 4;

    private SecureApplet() {
        // Initialize PIN with the maximum number of tries
        rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
        rsaKeyPair.genKeyPair();
        rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(DEFAULT_PIN, (short) 0, PIN_LENGTH);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SecureApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    private void areWeLogYet() {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if (selectingApplet()) {
            return;
        }

        if (buffer[ISO7816.OFFSET_CLA] != CLA_SIMPLEAPPLET) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if(!isPinSet)
        {
            changePinFirst(apdu); // si le pin est pas set le premier msg

            // est forcément pour changer le pin, si c'est pas le cas,
            // bah c'est pas le cas dommage ¯\_(ツ)_/¯ le pin est set maintenant.
        }
        else {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case INS_VERIFY:
                    /*verifyPin(apdu);*/
                    //byte[] buffer = apdu.getBuffer();
                    verifyPin(buffer);
                    break;
                case INS_CHANGE_PIN:
                    changePinPasFirst(apdu);
                    break;
                case INS_GET_PUBLIC_KEY:
                    getPublicKey(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }

    private void getPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short offset = ISO7816.OFFSET_CDATA;
        short expLen = rsaPublicKey.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        short modLen = rsaPublicKey.getModulus(buffer, (short) (offset + 4 + expLen));
        Util.setShort(buffer, (short) (offset + 2 + expLen), modLen);
        apdu.setOutgoingAndSend(offset, (short) (4 + expLen + modLen));
    }


    private void verifyPin(byte[] bArray) {
        if (bArray[ISO7816.OFFSET_LC] != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (!pin.check(bArray, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
            short code = (short) ((pin.getTriesRemaining() == 0) ? SW_BLOCKED : SW_PIN_FAILED_MORE);
            code = (pin.getTriesRemaining() == 2) ? SW_PIN_FAILED_2 : code;
            code = (pin.getTriesRemaining() == 1) ? SW_PIN_FAILED_1 : code;

            ISOException.throwIt(code);
        }
    }
    private void checkPin(byte[] bArray){
            if (bArray[ISO7816.OFFSET_LC] != PIN_LENGTH) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }

            if (!pin.check(bArray, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
                short error;
                switch (pin.getTriesRemaining()) {
                    case 2:
                        error = SW_PIN_FAILED_2;
                        break;
                    case 1:
                        error = SW_PIN_FAILED_1;
                        break;
                    case 0:
                        error = SW_BLOCKED;
                        break;
                    default:
                        error = SW_PIN_FAILED_MORE;
                        break;
                }
                ISOException.throwIt(error);
            }
        }

    private void changePinFirst(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        pin.update(buffer, ISO7816.OFFSET_CDATA, pinLength);
        isPinSet=true;
    }
    private void changePinPasFirst(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        areWeLogYet();
        byte pinLength = buffer[ISO7816.OFFSET_LC];
        pin.update(buffer, ISO7816.OFFSET_CDATA, pinLength);
        isPinSet=true;
    }
}
