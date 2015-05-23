
import java.net.SocketException;

/**
 *
 * @author Dario
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        new Thread(new Server.TCPServer(9004)).start();
        new Thread(new Client.TCPClient("127.0.0.1", 9004)).start();
    }

}
