import javax.smartcardio.*;
import java.util.Arrays;
import java.util.List;

public class JavaCardApp {

    public static void main(String[] args) {
        try {
            // Liste des lecteurs de cartes
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            // On prend le premier lecteur de carte (tu peux ajuster cela si tu as plusieurs lecteurs)
            CardTerminal terminal = terminals.get(0);

            // Connexion à la carte
            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();

            // Envoie la commande VERIFY pour entrer le PIN
            byte[] pinCommand = {(byte) 0xB0, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
            ResponseAPDU response = channel.transmit(new CommandAPDU(pinCommand));

            // Vérifie la réponse
            if (response.getSW() == 0x9000) {
                System.out.println("PIN correct. Accès autorisé !");
            } else {
                System.out.println("Code PIN incorrect. Accès refusé.");
            }

            // Déconnexion de la carte
            card.disconnect(true);

        } catch (CardException e) {
            e.printStackTrace();
        }
    }
}
