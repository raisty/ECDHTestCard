/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package classicapplet2;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;

/**
 *
 * @author Thotheolh
 */
public class ECDHTestCard extends Applet {

    private KeyPair kp1 = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
    private KeyPair kp2 = new KeyPair(KeyPair.ALG_EC_FP, (short) 256);
    private KeyAgreement ecdh1 = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
    private KeyAgreement ecdh2 = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
    public byte[] b1 = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
    
    /**
     * Installs this applet.
     *
     * @param bArray
     * the array containing installation parameters
     * @param bOffset
     * the starting offset in bArray
     * @param bLength
     * the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ECDHTestCard();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected ECDHTestCard() {
        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu
     * the incoming APDU
     */
    public void process(APDU apdu) {
        //Insert your code here
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) {
            try {
                // Gen KeyPair for kp1 and kp2
                kp1.genKeyPair();
                kp2.genKeyPair();
            } catch (CryptoException e) {
                ISOException.throwIt(e.getReason());
            }
            
            // Initialize ECDH for kp1 and kp2
            ecdh1.init(kp1.getPrivate());
            ecdh2.init(kp2.getPrivate());
            
            // Generate shared secrets for both ecdh kex setup
            ((ECPublicKey) kp2.getPublic()).getW(b1, (short) 0);
            ecdh1.generateSecret(b1, (short) 0, (short) 65, buffer, (short) 0);
            ((ECPublicKey) kp1.getPublic()).getW(b1, (short) 0);
            ecdh2.generateSecret(b1, (short) 0, (short) 65, buffer, (short) 65);
            
            // Output shared secrets
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) 256);
            apdu.sendBytesLong(buffer, (short) 0, (short) 256);

        }
    }
}
