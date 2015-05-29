
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 *
 * @author Dario
 */
public class Server implements Runnable {

    protected int srvPort;

    @Override
    public void run() {
    }

    private static String rmTime(String str) {
        String ogStr = str;
        try {
            Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(str);
            matcher.find();
            return (String) str.subSequence(0, matcher.start(0));
        } catch (IllegalStateException ex) {
        }
        return str;
    }

    public static class TCPServer extends Server {

        private SSLServerSocket srvSocket;
        private final Map<SSLSocket, String> usersL;
        private final Map<SSLSocket, String> toSend;
        private final ArrayList<String> srvMsg;
        private final String greetingStr;
        private final Long srvTime;
        private boolean srvRunning;

        public TCPServer() {
            String path = "";
            try {
                path = URLDecoder.decode(Server.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath(), "UTF-8");
                path = path.substring(0, path.lastIndexOf("/"));
                path = path.replaceAll("%20", " ");
                path += "/settings.conf";
            } catch (UnsupportedEncodingException | URISyntaxException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            }
            int port = 0;
            String str = "";
            boolean reset;
            do {
                reset = false;
                FileInputStream fIn = null;
                try {
                    fIn = new FileInputStream(new File(path));
                    BufferedReader bR = new BufferedReader(new InputStreamReader(fIn));
                    String line = "";
                    for (int i = 0; (line = bR.readLine()) != null;) {
                        Matcher matcher = Pattern.compile("\"(.+?)\"").matcher(line);
                        matcher.find();
                        if (i == 0) {
                            port = Integer.parseInt(matcher.group(1));
                            i++;
                        } else if (i == 1) {
                            str = matcher.group(1);
                            i++;
                        } else if (i == 2) {
                            if (Integer.parseInt(matcher.group(1)) == 1) {
                                str += new BufferedReader(new InputStreamReader(new URL("http://checkip.amazonaws.com").openStream())).readLine();
                                i++;
                            } else {
                                i += 2;
                            }
                        } else if (i == 3) {
                            str += matcher.group(1);
                        }
                    }
                } catch (IllegalStateException ex) {
                    System.out.println("ERROR in the configuration file!");

                    System.exit(0);
                } catch (FileNotFoundException ex) {
                    System.out.println("Missing configuration file, creating new default...");

                    BufferedWriter fOut = null;
                    try {
                        fOut = new BufferedWriter(new FileWriter(new File(path)));
                        fOut.write("port=\"9002\"\nwelcomeMsg=\"HELLO FROM \"\naddIPmsg=\"1\" #adds server ip to the welcome msg, 0 disable, 1 enables\npostIPmsg = \"!\" #adds text after ip, if addIPMsg is set to \"1\"");
                        fOut.flush();
                        fOut.close();
                        reset = true;
                    } catch (IOException ex1) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex1);
                    }
                } catch (IOException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } finally {
                    try {
                        if (fIn != null) {
                            fIn.close();
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            } while (reset);
            srvPort = port;
            greetingStr = str;
            usersL = new HashMap<>();
            toSend = new HashMap<>();
            srvMsg = new ArrayList<>();
            srvTime = (System.currentTimeMillis() / 1000L);
            srvRunning = true;
        }

        @Override
        public void run() {
            boolean portErr = false;
            do {
                try {
                    SSLServerSocketFactory sockF = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                    srvSocket = (SSLServerSocket) sockF.createServerSocket(srvPort);
                    srvSocket.setEnabledCipherSuites(new String[]{"SSL_DH_anon_WITH_RC4_128_MD5"});
                    portErr = false;
                } catch (IOException ex) {
                    portErr = true;
                    System.out.println("The port is already in use!");

                    String input;
                    do {
                        System.out.print("Input a new port: ");

                        input = new Scanner(System.in).nextLine();
                        if (input.matches("[0-9]+")) {
                            srvPort = Integer.parseInt(input);
                        } else {
                            System.out.println("Input a valid port!");

                            input = "";
                        }
                    } while (input.isEmpty());
                }
            } while (portErr);
            System.out.println("Server starting up on TCP port: " + srvPort);

            Thread checker = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (srvRunning) {
                        synchronized (srvMsg) {
                            for (String s : srvMsg) {
                                Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(s);
                                matcher.find();
                                long msgTime = Long.parseLong(matcher.group(1));
                                if ((srvTime - msgTime) >= 120000) {
                                    srvMsg.remove(s);
                                }
                            }
                        }
                        synchronized (toSend) {
                            Iterator iter = toSend.entrySet().iterator();
                            while (iter.hasNext()) {
                                Map.Entry ent = (Map.Entry) iter.next();
                                String s = (String) ent.getValue();
                                Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(s);
                                matcher.find();
                                long msgTime = Long.parseLong(matcher.group(1));
                                if ((srvTime - msgTime) >= 120000) {
                                    iter.remove();
                                }
                            }
                        }

                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException ex) {
                        }
                    }
                }
            });
            checker.start();
            while (srvRunning) {
                try {
                    SSLSocket c = (SSLSocket) srvSocket.accept();
                    System.out.println("Client connected from " + c.getInetAddress().getHostName());

                    synchronized (usersL) {
                        usersL.put(c, "");
                    }
                    new Thread(new TCPClientThread(c)).start();
                    Thread.sleep(500);
                } catch (IOException | InterruptedException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            checker.interrupt();
            if (!checker.interrupted()) {
                try {
                    checker.join();
                } catch (InterruptedException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            Iterator it = toSend.entrySet().iterator();
            while (it.hasNext()) {
                Entry ent = (Entry) it.next();
                SSLSocket s = (SSLSocket) ent.getKey();
                try {
                    s.close();
                } catch (IOException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

        }

        private class TCPClientThread implements Runnable {

            private final SSLSocket mySocket;
            private PrivateKey privKey;
            private PublicKey pubKey;
            private SecretKey AESkey;
            private SecretKey cAES;
            private PublicKey cRSA;
            private String userID;
            private boolean running = false, userIDchanged = false;
            private long myTime;

            private TCPClientThread(SSLSocket s) {
                mySocket = s;
                mySocket.setEnabledCipherSuites(new String[]{"SSL_DH_anon_WITH_RC4_128_MD5"});
                try {
                    mySocket.setKeepAlive(true);
                } catch (SocketException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
                KeyPairGenerator keyGen = null;
                KeyGenerator AESkeyGen = null;
                try {
                    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                    keyGen = KeyPairGenerator.getInstance("RSA");
                    keyGen.initialize(2048, random);
                    AESkeyGen = KeyGenerator.getInstance("AES");
                    AESkeyGen.init(128, random);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
                KeyPair pair = keyGen.genKeyPair();
                privKey = pair.getPrivate();
                pubKey = pair.getPublic();
                AESkey = AESkeyGen.generateKey();
            }

            @Override
            public void run() {
                getPubKey();
                System.out.println("SERVER: RSA decrypted received!");
                sendPubKey();
                System.out.println("SERVER: RSA encrypted sent!");
                sendAESKey();
                System.out.println("SERVER: AES double encrypted sent!");
                getAESKey();
                System.out.println("SERVER: AES double encrypted received & decrypted!");
                getUserID();
                running = true;
                myTime = (System.currentTimeMillis() / 1000L);
                System.out.println("ID \"" + userID + "\" received from IP: " + mySocket.getInetAddress().getHostName());
                if (userIDchanged) {
                    sendStr("(SRV-ID)" + userID + "(SRV-ID)" + timeTag());
                }
                sendStr(greetingStr + timeTag());
                listConnected();
                sendStr("(SRV)CONNECTED(SRV)" + timeTag());
                srvMsg.add("SERVER: " + userID + " has connected to the server! Say hi!" + timeTag());
                
                Thread InThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        while (running) {
                            String input = getStr();
                            String ogInput = input;
                            try {
                                Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(input);
                                matcher.find();
                                input = (String) input.subSequence(0, matcher.start(0));
                                if (matcher.group(1).matches("close")) {
                                    System.out.println(mySocket.getInetAddress().getHostName() + "/" + userID + " disconnected!");
                                    srvMsg.add("SERVER: " + userID + " disconnected!" + timeTag());
                                    synchronized (usersL) {
                                        usersL.remove(mySocket);
                                    }
                                    running = false;
                                } else if (matcher.group(1).matches("listusers")) {
                                    listConnected();
                                }
                            } catch (IllegalStateException ex) {
                            }
                            if ((!input.isEmpty() || input != null) && input.trim().length() > 0) {
                                synchronized (toSend) {
                                    toSend.put(mySocket, ogInput);
                                }
                            }
                        }

                    }
                });

                InThread.start();
                while (running) {
                    if (!toSend.isEmpty()) {
                        Iterator it = toSend.entrySet().iterator();
                        while (it.hasNext()) {
                            Entry ent = (Entry) it.next();
                            if (ent.getKey() != mySocket) {
                                synchronized (usersL) {
                                    String str1 = usersL.get((SSLSocket) ent.getKey());
                                    String str2 = (String) ent.getValue();
                                    Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(str2);
                                    matcher.find();
                                    String str3 = (String) str2.subSequence(matcher.start(1), str2.length());
                                    str3 = str3.replace(matcher.group(1) + "(ETX)", "");
                                    String str4 = (String) str2.subSequence(0, matcher.start(0));
                                    if (Integer.parseInt(matcher.group(1)) > myTime && !str3.contains("(ID)" + userID + "(ID)")) {
                                        sendStr(str1 + ": " + str4);
                                        toSend.put((SSLSocket) ent.getKey(), str2 + ("(ID)" + userID + "(ID)"));
                                    }
                                }
                            }
                        }
                    }
                    synchronized (srvMsg) {
                        if (!srvMsg.isEmpty()) {
                            for (int i = 0; i < srvMsg.size(); i++) {
                                String str = srvMsg.get(i);
                                Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(str);
                                matcher.find();
                                String str1 = (String) str.subSequence(0, matcher.start(0));
                                String str2 = (String) str.subSequence(matcher.start(1), str.length());
                                str2 = str2.replace(matcher.group(1) + "(ETX)", "");
                                if (Integer.parseInt(matcher.group(1)) > myTime && !str2.contains("(ID)" + userID + "(ID)")) {
                                    sendStr(str1);
                                    srvMsg.set(i, str + ("(ID)" + userID + "(ID)"));
                                }
                            }
                        }
                    }
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ex) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                InThread.interrupt();

                try {
                    InThread.join();
                } catch (InterruptedException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }

                try {
                    mySocket.close();
                } catch (IOException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
                userID = "";
                KeyPairGenerator keyGen = null;
                KeyGenerator AESkeyGen = null;

                try {
                    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                    keyGen = KeyPairGenerator.getInstance("RSA");
                    keyGen.initialize(2048, random);
                    AESkeyGen = KeyGenerator.getInstance("AES");
                    AESkeyGen.init(128, random);
                    keyGen.initialize(2048);
                    privKey = keyGen.genKeyPair().getPrivate();
                    pubKey = keyGen.genKeyPair().getPublic();
                    AESkey = AESkeyGen.generateKey();
                    cAES = AESkeyGen.generateKey();
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }

            }

            private void getPubKey() {
                if (cRSA == null) {
                    try {
                        ObjectInputStream sIn = new ObjectInputStream(mySocket.getInputStream());
                        cRSA = (PublicKey) sIn.readObject();
                    } catch (SSLException | SocketException | EOFException ex) {
                        System.out.println(mySocket.getInetAddress().getHostName() + " disconnected!");
                    } catch (IOException | ClassNotFoundException ex) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }

            private void sendPubKey() {
                try {
                    ObjectOutputStream sOut = new ObjectOutputStream(mySocket.getOutputStream());
                    ByteArrayOutputStream bOs = new ByteArrayOutputStream();
                    ObjectOutputStream out = new ObjectOutputStream(bOs);
                    try {
                        Cipher cipher = Cipher.getInstance(cRSA.getAlgorithm());
                        cipher.init(Cipher.ENCRYPT_MODE, cRSA);
                        PublicKey pk = pubKey;
                        out.writeObject(pk);
                        byte[] byteObj = bOs.toByteArray();
                        for (int i = 0, j = 0; j <= (byteObj.length / 200); i += 200, j++) {
                            byte[] serByteObj = Arrays.copyOfRange(byteObj, i, i + 200);
                            SealedObject sObj = new SealedObject(serByteObj, cipher);
                            sOut.writeObject(sObj);
                        }
                    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException ex) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    } finally {
                        sOut.flush();
                    }
                } catch (SSLException | SocketException | EOFException ex) {
                    System.out.println(mySocket.getInetAddress().getHostName() + " disconnected!");
                } catch (IOException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            private void sendAESKey() {
                try {
                    ObjectOutputStream sOut = new ObjectOutputStream(mySocket.getOutputStream());
                    ByteArrayOutputStream bOs = new ByteArrayOutputStream();
                    ObjectOutputStream out = new ObjectOutputStream(bOs);
                    try {
                        Cipher cipher1 = Cipher.getInstance(privKey.getAlgorithm());
                        cipher1.init(Cipher.ENCRYPT_MODE, privKey);
                        Cipher cipher2 = Cipher.getInstance(cRSA.getAlgorithm());
                        cipher2.init(Cipher.ENCRYPT_MODE, cRSA);
                        out.writeObject(AESkey);
                        byte[] serByteObj1 = cipher1.doFinal(bOs.toByteArray());
                        for (int i = 0; i < 4; i++) {
                            byte[] serByteObj2 = Arrays.copyOfRange(serByteObj1, 64 * i, 64 * i + 64);
                            SealedObject sObj = new SealedObject(serByteObj2, cipher2);
                            sOut.writeObject(sObj);
                        }
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    } finally {
                        sOut.flush();
                    }
                } catch (SSLException | SocketException | EOFException ex) {
                    System.out.println(mySocket.getInetAddress().getHostName() + " disconnected!");
                } catch (IOException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            private void getAESKey() {
                try {
                    ObjectInputStream sIn = new ObjectInputStream(mySocket.getInputStream());
                    Cipher dcipher1 = Cipher.getInstance(privKey.getAlgorithm());
                    dcipher1.init(Cipher.DECRYPT_MODE, privKey);
                    Cipher dcipher2 = Cipher.getInstance(cRSA.getAlgorithm());
                    dcipher2.init(Cipher.DECRYPT_MODE, cRSA);
                    byte[] serByteObj1 = null, serByteObj2 = null, serByteObj3 = null, serByteObj4 = null;
                    for (int i = 0; i < 4; i++) {
                        SealedObject sObj1 = (SealedObject) sIn.readObject();
                        if (i == 0) {
                            serByteObj1 = (byte[]) sObj1.getObject(dcipher1);
                        } else if (i == 1) {
                            serByteObj2 = (byte[]) sObj1.getObject(dcipher1);
                        } else if (i == 2) {
                            serByteObj3 = (byte[]) sObj1.getObject(dcipher1);
                        } else if (i == 3) {
                            serByteObj4 = (byte[]) sObj1.getObject(dcipher1);
                        }
                    }
                    byte[] fObj = new byte[serByteObj1.length + serByteObj2.length + serByteObj3.length + serByteObj4.length];
                    System.arraycopy(serByteObj1, 0, fObj, 0, serByteObj1.length);
                    System.arraycopy(serByteObj2, 0, fObj, serByteObj1.length, serByteObj2.length);
                    System.arraycopy(serByteObj3, 0, fObj, serByteObj1.length + serByteObj2.length, serByteObj3.length);
                    System.arraycopy(serByteObj4, 0, fObj, serByteObj1.length + serByteObj2.length + serByteObj3.length, serByteObj4.length);
                    cAES = (SecretKey) new ObjectInputStream(new ByteArrayInputStream(dcipher2.doFinal(fObj))).readObject();
                } catch (SSLException | SocketException | EOFException ex) {
                    System.out.println(mySocket.getInetAddress().getHostName() + " disconnected!");
                } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            private void sendStr(String str) {
                try {
                    Cipher cipher1 = Cipher.getInstance(cAES.getAlgorithm());
                    Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                    cipher1.init(Cipher.ENCRYPT_MODE, cAES);
                    cipher2.init(Cipher.ENCRYPT_MODE, AESkey);
                    ObjectOutputStream sOut = new ObjectOutputStream(mySocket.getOutputStream());
                    sOut.writeObject(cipher2.doFinal(cipher1.doFinal(str.getBytes(StandardCharsets.UTF_8))));
                    sOut.flush();
                } catch (SSLException | SocketException | EOFException ex) {
                    System.out.println(mySocket.getInetAddress().getHostName() + "/" + userID + " disconnected!");
                    srvMsg.add("SERVER: " + userID + " disconnected!" + timeTag());
                    synchronized (usersL) {
                        usersL.remove(mySocket);
                    }
                    running = false;
                } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            private String getStr() {
                try {
                    Cipher cipher1 = Cipher.getInstance(cAES.getAlgorithm());
                    Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                    cipher1.init(Cipher.DECRYPT_MODE, cAES);
                    cipher2.init(Cipher.DECRYPT_MODE, AESkey);
                    return new String(cipher2.doFinal(cipher1.doFinal((byte[]) new ObjectInputStream(mySocket.getInputStream()).readObject())), StandardCharsets.UTF_8);
                } catch (SSLException | SocketException | EOFException ex) {
                    System.out.println(mySocket.getInetAddress().getHostName() + "/" + userID + " disconnected!");

                    srvMsg.add("SERVER: " + userID + " disconnected!" + timeTag());
                    synchronized (usersL) {
                        usersL.remove(mySocket);
                    }
                    running = false;
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | ClassNotFoundException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
                return "";
            }

            private void getUserID() {
                userID = getStr();
                Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(userID);
                matcher.find();
                userID = (String) userID.subSequence(0, matcher.start(0));
                checkUserID();
                synchronized (usersL) {
                    usersL.put(mySocket, userID);
                }
            }

            private void checkUserID() {
                int i = 1;
                if (!usersL.isEmpty()) {
                    Iterator iter = usersL.entrySet().iterator();
                    while (iter.hasNext()) {
                        Map.Entry ent = (Map.Entry) iter.next();
                        String s = (String) ent.getValue();
                        if (s.equals(userID)) {
                            i++;
                        }
                    }
                }
                if (i != 1) {
                    userID = userID + "(" + i + ")";
                    userIDchanged = true;
                }
            }

            private void listConnected() {
                String str1 = "Connected users: ";
                String str2 = "";
                synchronized (usersL) {
                    Iterator it = usersL.entrySet().iterator();
                    while (it.hasNext()) {
                        Entry ent = (Entry) it.next();
                        String s = new String(usersL.get((SSLSocket) ent.getKey()).getBytes());
                        if (s.trim().length() > 0) {
                            str2 += s + ", ";
                        }
                    }
                }
                str2 = str2.substring(0, str2.length() - 2);
                sendStr(str1 + str2 + timeTag());
            }

            private String timeTag() {
                return "(STX)" + (System.currentTimeMillis() / 1000L) + "(ETX)";
            }
        }
    }

    public static class UDPServer extends Server {

        private DatagramSocket srvSocket;

        public UDPServer(int port) {
            srvPort = port;
        }

        public void start() {
            boolean portErr = false;
            do {
                try {
                    srvSocket = new DatagramSocket(srvPort);
                    portErr = false;
                } catch (SocketException ex) {
                    portErr = true;
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    System.out.println("The port is already in use!");

                    String input;
                    do {
                        System.out.print("Input a new port: ");
                        input = new Scanner(System.in).nextLine();
                        if (input.matches("[0-9]+")) {
                            srvPort = Integer.parseInt(input);
                        } else {
                            System.out.println("Input a valid port!");
                            input = "";
                        }
                    } while (input.isEmpty());
                }
            } while (portErr);
            System.out.println("Server starting up on UDP port: " + srvPort);
            run();
        }
    }
}
