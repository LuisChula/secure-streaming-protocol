import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.net.InetSocketAddress;

import java.net.SocketAddress;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.nio.file.Files;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

class SSHSocket extends SSPSocket {
	private KeyAgreement keyAgree;
	private KeyPair pair, pairDH;
	private String movie, password;
	private Properties properties;

	public SSHSocket(SocketAddress addr, String file, String password, String movie) throws Exception {
		super(addr);
		System.out.println(addr.toString());
		generateKey();
		this.movie = movie;
		this.password = password;
		setProperties(file);
		startHandshake(addr);
	}

	public SSHSocket(String file) throws Exception {
		super(new InetSocketAddress("localhost", 9998));
		generateKey();
		setProperties(file);
		waitForProxy();
	}
	
	private void setProperties(String file) throws Exception {
		InputStream inputStream = new FileInputStream(file);
        properties = new Properties();
        properties.load(inputStream);
	}

	private void generateKey() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(4096);
       	pair = keyGen.generateKeyPair();

        keyAgree = KeyAgreement.getInstance("DH", "BC");
        keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(2048);
        pairDH = keyGen.generateKeyPair();

        keyAgree.init(pairDH.getPrivate());
	}

	//server
	private void waitForProxy() throws Exception {
		System.out.println("wait proxy");
		SecureRandom rand = new SecureRandom(); 
        byte[] N2 = ByteBuffer.allocate(4).putInt(rand.nextInt()).array();
		authenticatedHelloChallenge(N2);
		byte[] N4 = keySaEstablishment(N2);
		endHandshake(N4);
	}

	public void startHandshake(SocketAddress addr) throws Exception  {				
		
		byte[] N1 = startHandshake();
		
		byte[] N3 = responseToChallenge(N1);
		
		handshakeDone(N3);
	}

	public void send(DatagramPacket p) throws Exception {
		super.send(p, (byte)0x01);
	}
	
	private byte[] getX(byte[] N1, byte[] N2, Message m) throws Exception {
		
		byte[] publicKey = pair.getPublic().getEncoded();
		byte[] hN1 = super.getCS().getHash(N1, "SHA-256");
		        
        byte[] output = ByteBuffer
		        .allocate(publicKey.length + hN1.length + N2.length)
		        .put(publicKey).put(hN1).put(N2)
		        .array();
        
        m.add(publicKey);m.add(hN1);m.add(N2);
        
		return output;
	}
	
	public byte[] serialize(Object obj) throws IOException {
	    ByteArrayOutputStream out = new ByteArrayOutputStream();
	    ObjectOutputStream os = new ObjectOutputStream(out);
	    os.writeObject(obj);
	    return out.toByteArray();
	}
	
	public Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
	    ByteArrayInputStream in = new ByteArrayInputStream(data);
	    ObjectInputStream is = new ObjectInputStream(in);
	    return is.readObject();
	}
	
	private List<byte[]> recieveData() throws Exception {
		byte[] buff = new byte[4096];
		DatagramPacket inP = new DatagramPacket(buff, buff.length);	
		super.getSocket().receive(inP);
		byte[] data = inP.getData();

		Message m = (Message) deserialize(data);
		List<byte[]> l = m.getMessage();
		
		return l;
	}

	private void authenticatedHelloChallenge(byte[] N2) throws Exception {
		byte[] buff = new byte[4096];
			
		DatagramPacket inP = new DatagramPacket(buff, buff.length);
		super.getSocket().receive(inP);
		
		byte[] data = inP.getData();
		data = Arrays.copyOfRange(data, 0, inP.getLength());
		
		Message msg = (Message) deserialize(data);
		List<byte[]> m = msg.getMessage();
		
		byte[] hello = m.get(1);
		byte[] proxyID = m.get(2);
		byte[] movie = m.get(3);
		byte[] N1 = m.get(4);
		byte[] pwdcs = m.get(5);
		byte[] epwd = m.get(6);
		
		this.movie = new String(movie, StandardCharsets.UTF_8);
		String s = new String(hello, StandardCharsets.UTF_8);
		if(!s.equalsIgnoreCase("hello")) {
			System.out.println("Invalid hello msg :(");
			System.exit(-1);
		}
		
		String alg = new String(pwdcs, StandardCharsets.UTF_8);
		byte[] salt = Utils.hexToBytes(properties.getProperty("salt"));
		
		byte[] X = ByteBuffer
		        .allocate(hello.length + proxyID.length + movie.length + N1.length)
		        .put(hello).put(proxyID).put(movie).put(N1)
		        .array();
		
		byte[] hX = super.getCS().getHash(X, "SHA1");
		password = properties.getProperty("password");
		
		super.getCS().verifyEpwd(epwd, hX, salt, password, alg);		
		
		msg = new Message();
		
		String sigcryptosuite = "SHA256withRSA";
		msg.add(sigcryptosuite.getBytes());		
		
		X = getX(N1, N2, msg);
		byte[] signedX = super.getCS().sign(sigcryptosuite, pair.getPrivate(), X);
		msg.add(signedX);
		
		byte[] header = super.getHeader(sigcryptosuite.getBytes().length + 
				X.length + signedX.length, (byte)0x01);
		msg.add(0, header);
		
		byte[] output = serialize(msg);
		
		SocketAddress addr = inP.getSocketAddress();
		DatagramPacket outP = new DatagramPacket(output, output.length, addr);
		super.getSocket().send(outP);
	}
	
	private byte[] responseToChallenge(byte[] N1) throws Exception{
		List<byte[]> l = recieveData();
		
		byte[] sigcryptosuite = l.get(1);
		byte[] pubKeyS = l.get(2);
		byte[] hN1 = l.get(3);
		byte[] N2 = l.get(4);
		byte[] sigX = l.get(5);
		
		String s = new String(sigcryptosuite, StandardCharsets.UTF_8);
		System.out.println(s);
		
		byte[] message = ByteBuffer
		        .allocate(pubKeyS.length + hN1.length + N2.length)
		        .put(pubKeyS).put(hN1).put(N2)
		        .array();
		
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKeyS));
		super.getCS().verifySignature(s, publicKey, message, sigX);
		System.out.println("Verify Hash");
		super.getCS().digest(hN1, N1, "SHA-256");
		System.out.println("Verify Hash");
		
		String sig = "SHA256withRSA";
		sigcryptosuite = sig.getBytes();
		byte[] publicKeyP = pair.getPublic().getEncoded();
		SecureRandom rand = new SecureRandom(); 
        byte[] N3 = ByteBuffer.allocate(4).putInt(rand.nextInt()).array();
        byte[] DHpublicC = pairDH.getPublic().getEncoded();
        
        byte[] hN2 = super.getCS().getHash(N2, "SHA-256");
        byte[] X = ByteBuffer
	        .allocate(hN2.length + N3.length + DHpublicC.length)
	        .put(hN2).put(N3).put(DHpublicC)
	        .array();
        sigX = super.getCS().sign(sig, pair.getPrivate(), X);
        
        Message m = new Message();
        m.add(sigcryptosuite);
        m.add(publicKeyP);
        m.add(hN2);
        m.add(N3);
        m.add(DHpublicC);
        m.add(sigX);
        
        int aux = sigcryptosuite.length + publicKeyP.length + hN2.length + N3.length + DHpublicC.length + sigX.length;
        m.add(0, super.getHeader(aux, (byte)0x01));
        
        byte[] output = serialize(m);
        
        DatagramPacket outP = new DatagramPacket(output, output.length, new InetSocketAddress("localhost", 9998));
		super.getSocket().send(outP);

		return N3;
	}
	
	private byte[] keySaEstablishment(byte[] N2) throws Exception {
		List<byte[]> data = recieveData();
		
		byte[] sigcryptosuite = data.get(1);
		byte[] pubKeyP = data.get(2);
		byte[] hN2 = data.get(3);
		byte[] N3 = data.get(4);
		byte[] DHpublicC = data.get(5);
		byte[] sigX = data.get(6);

		super.getCS().digest(hN2, N2, "SHA-256");

		byte[] x = ByteBuffer.allocate(hN2.length + N3.length + DHpublicC.length)
							 .put(hN2).put(N3).put(DHpublicC).array();
		
		String alg = new String(sigcryptosuite, StandardCharsets.UTF_8);
		PublicKey publicKeyP = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKeyP));
		super.getCS().verifySignature(alg, publicKeyP, x, sigX);
		
		byte[] hN3 = super.getCS().getHash(N3, "SHA-256");
		byte[] DHpublicS = pairDH.getPublic().getEncoded();
		SecureRandom rand = new SecureRandom(); 
        byte[] N4 = ByteBuffer.allocate(4).putInt(rand.nextInt()).array();
        
        String file = "Server_SSPConfigs.conf";
        byte[] filesB = generateFile(file, DHpublicC);

        byte[] plain = ByteBuffer
	        	.allocate(filesB.length + N4.length)
	        	.put(N4).put(filesB)
	        	.array();
        
        byte[] cipherText = super.getCS().encrypt(plain, publicKeyP);

        sigX = super.getCS().sign(alg, pair.getPrivate(), DHpublicS);
        sigcryptosuite = ByteBuffer.allocate(alg.getBytes().length + 1 + pair.getPublic().getEncoded().length)
        						   .put(alg.getBytes()).put((byte)0x00).put(pair.getPublic().getEncoded()).array();
        Message m = new Message();
        m.add(sigcryptosuite);
        m.add(hN3);
        m.add(DHpublicS);
        m.add(cipherText);
        m.add(sigX);

        m.add(0, super.getHeader(sigcryptosuite.length + hN3.length + DHpublicS.length + cipherText.length + sigX.length, (byte)0x01));

        byte[] output = serialize(m);
        
        DatagramPacket outP = new DatagramPacket(output, output.length, new InetSocketAddress("localhost", 9999));
		super.getSocket().send(outP);
		
		super.setCryptoStuff(file);
		
		return N4;
	}

	public void handshakeDone(byte[] N3) throws Exception {
		List<byte[]> data = recieveData();

		byte[] sigcryptosuite = data.get(1);
		byte[] hN3 = data.get(2);
		byte[] DHpublicS = data.get(3);
		byte[] cipher = data.get(4);
		byte[] sigX = data.get(5);

		int i = 0;
		for(; i < sigcryptosuite.length; i++)
			if(sigcryptosuite[i] == 0x00)
				break;
		
		super.getCS().digest(hN3, N3, "SHA-256");
		System.out.println("Verifying signature on handshakeDone! " + i);
		PublicKey publicKey = KeyFactory.getInstance("RSA")
					.generatePublic(new X509EncodedKeySpec(Arrays.copyOfRange(sigcryptosuite, i + 1, sigcryptosuite.length)));
		String alg = new String(Arrays.copyOfRange(sigcryptosuite, 0, i), StandardCharsets.UTF_8);
		super.getCS().verifySignature(alg, publicKey, DHpublicS, sigX);

		byte[] plain = super.getCS().decrypt(cipher, pair.getPrivate());

		byte[] finish = "FINISHED".getBytes();
		byte[] N4 = Arrays.copyOfRange(plain, 0, 4);
		byte[] fileBytes = Arrays.copyOfRange(plain, 4, plain.length);

		byte[] hN4 = super.getCS().getHash(N4, "SHA-256");

		String file = "Proxy_SSPConfigs.conf";
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(fileBytes);
		}
		super.setCryptoStuff(file);

		byte[] message = ByteBuffer.allocate(finish.length + hN4.length).put(finish).put(hN4).array();
		cipher = super.getCS().encrypt(message);

		Message m = new Message();
		m.add(0, super.getHeader(finish.length + hN4.length, (byte)0x01));
		m.add(cipher);

		byte[] output = serialize(m);
        
        DatagramPacket outP = new DatagramPacket(output, output.length, new InetSocketAddress("localhost", 9998));
		super.getSocket().send(outP);
	}
	
	private void endHandshake(byte[] N4) throws Exception {
		List<byte[]> data = recieveData();
		
		byte[] cipher = data.get(1);
		
		byte[] plain = super.getCS().decrypt(cipher);

		byte[] a = Arrays.copyOfRange(plain, 0, 8);
		String finish = new String(a, StandardCharsets.UTF_8);
		byte[] hN4 = Arrays.copyOfRange(plain, 8, plain.length);
		
		if(!finish.toString().equals("FINISHED")){
        	System.out.println("Invalid end message :(");
        	System.exit(-1);
        }
        super.getCS().digest(hN4, N4, "SHA-256");
	}
	
	private byte[] generateFile(String file, byte[] DHpublicC) throws Exception {
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[16];
		randomSecureRandom.nextBytes(iv);

		byte[] mac1K = new byte[8];
		randomSecureRandom.nextBytes(mac1K);		

		byte[] mac2K = new byte[16];
		randomSecureRandom.nextBytes(mac2K);

		String ivstr = Utils.toHex(iv);

		PublicKey pubC = KeyFactory.getInstance("DH").generatePublic(new X509EncodedKeySpec(DHpublicC));
		keyAgree.doPhase(pubC, true);
		SecretKey secretKey = keyAgree.generateSecret("AES");

		String secK = Utils.toHex(secretKey.getEncoded());
		
		File configFile = new File(file);
		Properties props = new Properties();
	    props.setProperty("CRYPTO-CIPHERSUITE", "AES/CBC/PKCS5Padding");
	    props.setProperty("MAC1-CIPHERSUITE","HmacSHA256");
	    props.setProperty("MAC2-CIPHERSUITE","HmacSHA1");
	    props.setProperty("IV",ivstr);
	    props.setProperty("SESSION-KEYSIZE", ""+secretKey.getEncoded().length);
	    props.setProperty("SESSION-KEY",secK);
	    props.setProperty("MAC1-KEYSIZE",""+mac1K.length);
	    props.setProperty("MAC1-KEY", Utils.toHex(mac1K));
	    props.setProperty("MAC2-KEYSIZE",""+mac2K.length);
	    props.setProperty("MAC2-KEY", Utils.toHex(mac2K));
	    
	    FileWriter writer = new FileWriter(configFile);
	    props.store(writer, null);
	    writer.close();

	    byte[] filesB = Files.readAllBytes(configFile.toPath());
	    
	    return filesB;
	}
	
	private byte[] startHandshake() throws Exception {
		Message m = new Message();
		byte[] hello = "HELLO".getBytes();
		SecureRandom rand = new SecureRandom();
		byte[] proxyID = Utils.hexToBytes(properties.getProperty("proxyID"));
		byte[] requestedMovie = movie.getBytes();
		byte[] N1 = ByteBuffer.allocate(4).putInt(rand.nextInt()).array();
		String alg = "PBEWithMD5AndTripleDES";
		byte[] pwdcs = alg.getBytes();
		byte[] salt = Utils.hexToBytes(properties.getProperty("salt"));
		
		byte[] X = ByteBuffer
		        .allocate(hello.length + proxyID.length + requestedMovie.length + N1.length)
		        .put(hello).put(proxyID).put(requestedMovie).put(N1)
		        .array();
		byte[] sha1X = super.getCS().getHash(X, "SHA1");
		
		byte[] epwd = super.getCS().getEpwd(sha1X, salt, password, alg);
		
		m.add(hello);
		m.add(proxyID);
		m.add(requestedMovie);
		m.add(N1);
		
		byte[] header = super.getHeader(X.length + pwdcs.length + epwd.length, (byte)0x01);
		
		m.add(0, header);
		m.add(pwdcs);
		m.add(epwd);
		
		byte[] output = serialize(m);
		
		DatagramPacket outP = new DatagramPacket(output, output.length, new InetSocketAddress("localhost", 9998));
		super.getSocket().send(outP);
		
		return N1;
	}

	public String getMovie() {
		return movie;
	}
}