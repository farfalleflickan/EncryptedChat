/**
 *
 * @author Dario
 */
public class ClientStart {
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        new Client.TCPClient("127.0.0.1", 9004).run();
    }
}
