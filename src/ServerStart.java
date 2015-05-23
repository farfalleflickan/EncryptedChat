
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Dario Rostirolla, rostirolladario@gmail.com
 */
public class ServerStart {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
//        try {
//            new Server.TCPServer(9004, new BufferedReader(new InputStreamReader(new URL("http://checkip.amazonaws.com").openStream())).readLine()).run();
            new Server.TCPServer().run();
//        } catch (MalformedURLException ex) {
//            Logger.getLogger(ServerStart.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (IOException ex) {
//            Logger.getLogger(ServerStart.class.getName()).log(Level.SEVERE, null, ex);
//        }
    }
    
}
