import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Properties;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CryptoException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.BadPaddingException;


public class CryptoStuff {

    private String ALGORITHM;
    private String TRANSFORMATION;
    private byte[] keyBytes;
    private byte[] ivBytes;
    private byte[] mac1Bytes;
    private byte[] mac2Bytes;
    
    private Properties properties;

    public CryptoStuff() {}
    
    public CryptoStuff(String file, boolean isFirstFase) throws Exception {
    	InputStream inputStream = new FileInputStream(file);
        properties = new Properties();
        properties.load(inputStream);
        
        ALGORITHM = properties.getProperty("CRYPTO-CIPHERSUITE").split("/")[0];
        TRANSFORMATION = properties.getProperty("CRYPTO-CIPHERSUITE");
        
    	if(isFirstFase)
    		firstFase();
    	else
    		secondFase();
    }
    
    
    private void secondFase() throws Exception {        
        keyBytes = Utils.hexStringToByteArray(properties.getProperty("SESSION-KEY"));
        ivBytes = Utils.hexStringToByteArray(properties.getProperty("IV"));
        mac1Bytes = Utils.hexStringToByteArray(properties.getProperty("MAC1-KEY"));
        mac2Bytes = Utils.hexStringToByteArray(properties.getProperty("MAC2-KEY"));
    }
    
    private void firstFase() throws Exception {
        if(!properties.getProperty("CRYPTO-CIPHERSUITE").equalsIgnoreCase("null"))
            keyBytes = Utils.hexToBytes(properties.getProperty("SESSION-KEY"));
        if(!properties.getProperty("IV").equalsIgnoreCase("null"))
            ivBytes = Utils.hexToBytes(properties.getProperty("IV"));
        if(!properties.getProperty("MAC1-CIPHERSUITE").equalsIgnoreCase("null"))
            mac1Bytes = Utils.hexToBytes(properties.getProperty("MAC1-KEY"));
        if(!properties.getProperty("MAC2-CIPHERSUITE").equalsIgnoreCase("null"))
            mac2Bytes = Utils.hexToBytes(properties.getProperty("MAC2-KEY"));
    }
    
    public static byte[] toByteArray(String string) {
        byte[]	bytes = new byte[string.length()];
        char[]  chars = string.toCharArray();
        
        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte)chars[i];
        }
        
        return bytes;
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public byte[] decrypt(byte[] input) throws CryptoException {
        return doCrypto(Cipher.DECRYPT_MODE, input);
    }

    public byte[] encrypt(byte[] input) throws CryptoException {
        return doCrypto(Cipher.ENCRYPT_MODE, input);
    }

    private byte[] doCrypto(int cipherMode, byte[] inputBytes) throws CryptoException {
        try {

            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            Key secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey, ivSpec);
            return cipher.doFinal(inputBytes);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException
        | InvalidKeyException | BadPaddingException | IllegalBlockSizeException
        | InvalidAlgorithmParameterException ex) {
        	throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }

    public byte[] decrypt(byte[] input, PrivateKey key) throws CryptoException {
        return doCrypto(Cipher.DECRYPT_MODE, input, key);
    }

    public byte[] encrypt(byte[] input, PublicKey key) throws CryptoException {
        return doCrypto(Cipher.ENCRYPT_MODE, input, key);
    }

    public byte[] doCrypto(int cipherMode, byte[] inputBytes, Key key) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
            cipher.init(cipherMode, key);
            return cipher.doFinal(inputBytes);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
        | InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }

    public int getMac1Length() throws Exception {
        String mac = properties.getProperty("MAC1-CIPHERSUITE");
        return mac.equals("NULL") ? 0 : Mac.getInstance(mac).getMacLength();
    }
    
    public byte[] tamperedWithMac1(byte[] input) throws Exception {
    	String mac = properties.getProperty("MAC1-CIPHERSUITE");

        if(mac.equals("NULL")) 
            return new byte[0];
		
		SecretKeySpec MacKey = new SecretKeySpec(mac1Bytes, mac);
		
		Mac hMac = Mac.getInstance(mac);
	    Key hMacKey = new SecretKeySpec(MacKey.getEncoded(), mac);
		System.out.println("MAC length: " + hMac.getMacLength());
		hMac.init(hMacKey);
		//hMac.update(input);
        return hMac.doFinal(input);
    }

    public int getMac2Length() throws Exception {
        String mac = properties.getProperty("MAC2-CIPHERSUITE");
        return Mac.getInstance(mac).getMacLength();
    }
    
    public byte[] tamperedWithMac2(byte[] input) throws Exception {
    	String mac = properties.getProperty("MAC2-CIPHERSUITE");
		
		SecretKeySpec MacKey = new SecretKeySpec(mac2Bytes, mac);
		
		Mac hMac = Mac.getInstance(mac);
	    Key hMacKey = new SecretKeySpec(MacKey.getEncoded(), mac);
        System.out.println("MAC length: " + hMac.getMacLength());
		   
		hMac.init(hMacKey);
        hMac.update(input);
        return hMac.doFinal();
    }
    
    public byte[] getHash(byte[] input, String alg) throws Exception {
    	MessageDigest   hash = MessageDigest.getInstance(alg, "BC");
    	return hash.digest(input);
    }
    
    public byte[] getEpwd(byte[] X, byte[] salt, String password, String alg) throws Exception {
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory
				.getInstance(alg);
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
		
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
		Cipher cipher = Cipher.getInstance(alg);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
		
		return cipher.doFinal(X);
	}

    public byte[] sign(String algorithm, PrivateKey priv, byte[] message) throws Exception {

        Signature signature = Signature.getInstance(algorithm);

        signature.initSign(priv);
        signature.update(message);

        return signature.sign();
    }

    public void verifySignature(String algorithm, PublicKey pub, byte[] message, byte[] sigBytes) throws Exception {
        Signature signature = Signature.getInstance(algorithm);

        signature.initVerify(pub);
        signature.update(message);
        
        if(!signature.verify(sigBytes)) {
        	System.out.println("Invalid signature :(");
        	System.exit(-1);
        }
    }
    
    public void digest(byte[] hM, byte[] m, String alg) throws Exception {
    	byte[] hM2 = getHash(m, alg);
    	if(!MessageDigest.isEqual(hM2, hM)) {
        	System.out.println("Invalid hash :(");
        	System.exit(-1);
        }
    }
    
    public void verifyEpwd(byte[] epwd, byte[] hX, byte[] salt, String password, String alg) throws Exception {
    	PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory
				.getInstance(alg);
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
		
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
		Cipher cipher = Cipher.getInstance(alg);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
		
		byte[] d = cipher.doFinal(epwd);
		
		if(!MessageDigest.isEqual(hX, d)) {
        	System.out.println("Invalid Epwd :(");
        	System.exit(-1);
        }
    }

}
