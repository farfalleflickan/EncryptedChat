
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramSocket;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
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

    public static class TCPServer extends Server {

        private SSLServerSocket srvSocket;
        private Map<SSLSocket, String> usersL;
        private Map<SSLSocket, String> toSend;
        private ArrayList<String> srvMsg;

        public TCPServer(int port) {
            srvPort = port;
            usersL = new HashMap<>();
            toSend = new HashMap<>();
            srvMsg = new ArrayList<>();
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
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    System.out.println("The port is already in use!");
                    String input;
                    do {
                        System.out.print("Input a new port: ");
                        input = new Scanner(System.in).next();
                        if (input.matches("[0-9]+")) {
                            srvPort = Integer.parseUnsignedInt(input);
                        } else {
                            System.out.println("Input a valid port!");
                            input = "";
                        }
                    } while (input.isEmpty());
                }
            } while (portErr);
            System.out.println("Server starting up on TCP port: " + srvPort);
            while (true) {
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
        }

        private class TCPClientThread implements Runnable {

            private final SSLSocket mySocket;
            private final PrivateKey privKey;
            private final PublicKey pubKey;
            private final SecretKey AESkey;
            private SecretKey cAES;
            private PublicKey cRSA;
            private String userID;
            private HashMap<SSLSocket, String> myL;
            private ArrayList<String> mySrvL;
            private boolean running;

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
                    AESkeyGen.init(128);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
                KeyPair pair = keyGen.genKeyPair();
                privKey = pair.getPrivate();
                pubKey = pair.getPublic();
                AESkey = AESkeyGen.generateKey();
                myL = new HashMap<>();
                mySrvL = new ArrayList<>();
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
                synchronized (srvMsg) {
                    srvMsg.add(userID+" has connected!");
                }
                running = true;
                try {
                    sendStr("WELCOME TO " + new BufferedReader(new InputStreamReader(new URL("http://checkip.amazonaws.com").openStream())).readLine());
                } catch (MalformedURLException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                }
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        while (running) {
                            String input = getStr();
                            synchronized (toSend) {
                                toSend.put(mySocket, input);
                            }
                        }
                    }
                }).start();
                while (running) {
                    if (usersL.size() > 1 && toSend.isEmpty() == false) {
                        synchronized (toSend) {
                            myL = (HashMap<SSLSocket, String>) toSend;
//                            for (Entry ent : toSend.entrySet()) {
//                                if (ent.getKey() != mySocket) {
//                                    sendStr(usersL.get(ent.getKey()) + ": " + ent.getValue());
//                                }
//                            }
                        }
                        Iterator it = toSend.entrySet().iterator();
                        while (it.hasNext()) {
                            Entry ent = (Entry) it.next();
                            if (ent.getKey() != mySocket) {
                                synchronized (usersL) {
                                    sendStr(usersL.get(ent.getKey()) + ": " + ent.getValue());
                                    it.remove();
                                }
                            }
                        }
                    }
                    if (!srvMsg.isEmpty()) {
                        mySrvL = srvMsg;
                        for (int i = mySrvL.size() - 1; i > 0; i--) {
                            sendStr(mySrvL.get(i));
                            mySrvL.remove(i);
                        }
                    }
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ex) {
                        Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }

            private void getPubKey() {
                if (cRSA == null) {
                    try {
                        ObjectInputStream sIn = new ObjectInputStream(mySocket.getInputStream());
                        cRSA = (PublicKey) sIn.readObject();
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
                } catch (IOException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
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
                } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            private void sendStr(String str) {
                try {
                    Cipher cipher1 = Cipher.getInstance(cAES.getAlgorithm());
                    Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                    cipher1.init(Cipher.ENCRYPT_MODE, cAES);
                    cipher2.init(Cipher.ENCRYPT_MODE, AESkey);
                    ObjectOutputStream sOut = new ObjectOutputStream(mySocket.getOutputStream());
                    sOut.writeObject(cipher2.doFinal(cipher1.doFinal(str.getBytes())));
                    sOut.flush();
                } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            private String getStr() {
                try {
                    Cipher cipher1 = Cipher.getInstance(cAES.getAlgorithm());
                    Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                    cipher1.init(Cipher.DECRYPT_MODE, cAES);
                    cipher2.init(Cipher.DECRYPT_MODE, AESkey);
                    return new String(cipher2.doFinal(cipher1.doFinal((byte[]) new ObjectInputStream(mySocket.getInputStream()).readObject())));
                } catch (SocketException ex) {
                    System.out.println(mySocket.getInetAddress().getHostName() + " disconnected!");
                    srvMsg.add("SERVER: " + userID + " disconnected!");
                    synchronized (usersL) {
                        usersL.remove(mySocket);
                    }
                    running = false;
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | ClassNotFoundException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
                return "";
            }

            private void getUserID() {
                userID = getStr();
                synchronized (usersL) {
                    usersL.put(mySocket, userID);
                }
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
                        input = new Scanner(System.in).next();
                        if (input.matches("[0-9]+")) {
                            srvPort = Integer.parseUnsignedInt(input);
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
