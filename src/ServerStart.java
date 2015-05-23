/**
 *
 * @author Dario Rostirolla, rostirolladario@gmail.com
 */
public class ServerStart {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        new Server.TCPServer(9004).run();
    }
    
}
