import java.io.*;
import java.security.*;
import javax.crypto.*;
import java.util.*;
import java.nio.charset.Charset;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.math.BigInteger;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import java.math.*;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
//Simple crypto class
public class Crypto{
    private static String g = "c4a04391743a1a270af5bec952a84951229560b5a4b7ca1a24316836"+
					   "b9031943f4f2cb64aa854f7ca9546530ed11dce0f54691baec98b1c6"+
					   "a8de9b80ae96f684c0b84dfdcc505951a896ce3f4d07556e93f00dfd"+
					   "1c64a76c10721afb390ee2af5515fe40d1a0cb97c9eb9162da33981c"+
					   "d9260de4f6721b6421b243d39dc0c412";

	private static String N = "e438f5f9e266d547f2ce63db4f2ccef46c4f2ebdac1a5eb703ae1ce9"+
					   "afae2100a2ea6922df52d6dbada5ff0c3dc510613275918b6a26b19f"+
					   "c1e5625e58c2a045492a2283da75ec38a9f0748c87b9db06d72c65bd"+
					   "ca21fdf3cc02ac48165d539996d7aa2f99b4a39d370cbaf0e4a07b77"+
					   "49899c3a5d73f54b792094857b3693d3";
	Provider bc;

    public Crypto(){
        Security.addProvider(new BouncyCastleProvider());
        try{
        bc=Security.getProvider("BC");
        }catch(Exception e){};
        if (bc == null){
            System.out.println("Bouncy Castle provider is not available! ");
            System.exit(-1);
        }
    }

//*********** Method for testing ************************
    // public static void main(String args[])throws NoSuchProviderException{
    //     Crypto c = new Crypto();
    //     //Test AES with CBC
    //     String mes = "slkajfklajfklasjfklasjfkdlsajfkdsljfkdsaljfdksljfioewfewu iqnuioecoanrownc3ijioendsnfkldsnjfean fioe uf";
    //     Key aes = c.gen_AESKey();
    //     byte[] ec=c.aes_cbc_encrypt(aes, mes.getBytes());
    //     byte[] mes2 = c.aes_cbc_decrypt(aes, ec);
    //     System.out.println(mes);
    //     System.out.println(new String(mes2));
    //     //Test RSA with fake_ECB mode
    //     String m0 = "sdsrwbcroiu44vby438b7vop8`b589uiwbyiuwbruiwbrwjgergjoi;ioerjg";
    //     KeyPair rsa = c.gen_RSAKey(1024);
    //     byte[] sc_rsa = c.rsa_seg_encrypt(rsa.getPublic(), m0.getBytes());
    //     byte[] m1 = c.rsa_seg_decrypt(rsa.getPrivate(), sc_rsa);
    //     System.out.println(m0);
    //     System.out.println(new String(m1));
    //     //Test large files
    //     KeyPair rsa_big = c.gen_RSAKey(4096);
    //     byte[] a1 = c.rsa_sign_obj("rannn", rsa.getPrivate());
    //     Timestamp ts= new Timestamp(System.currentTimeMillis());
    //     ArrayList<Object> arl = new ArrayList<Object>();
    //     arl.add(a1);
    //     arl.add(ts);
    //     arl.add(aes);
    //     byte[] re = c.rsa_encrypt_obj(arl, rsa_big.getPublic());
    //     System.out.println("Success!!!");

    // }
        //AES 
    public SecretKey gen_AESKey(){
        SecretKey key_aes = null;
        try{
            KeyGenerator gen_aes=KeyGenerator.getInstance("AES", bc);
            gen_aes.init(256);
            key_aes=gen_aes.generateKey();
        }
        catch(Exception e){
            System.out.println("Exception on AES Key Generation: ");
            e.printStackTrace();
            System.exit(-1);
        }
        return key_aes;
    }

    public KeyPair gen_RSAKey(int key_len){
        KeyPair rsa_pair = null;
        try{
            KeyPairGenerator gen_rsa=KeyPairGenerator.getInstance("RSA", bc);
            gen_rsa.initialize(key_len);
            rsa_pair=gen_rsa.genKeyPair();
        }
        catch(Exception e){
            System.out.println("Exception on RSA Key Generation: ");
            e.printStackTrace();
            System.exit(-1);
        }
        return rsa_pair;
    }


    public byte[] aes_cbc_encrypt(Key key, byte[] text){
        byte[] result=null;
        try{
            SecureRandom rng = new SecureRandom();
            byte[] iv=new byte[16];
            rng.nextBytes(iv);
            Cipher cipher=Cipher.getInstance("AES/CBC/PKCS7Padding", bc);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] encrypted=cipher.doFinal(text);
            result=new byte[encrypted.length + 16];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        }catch(Exception e){
            System.out.println("Exception on cbc encrypt: " );
            e.printStackTrace();
        }
        return result;
    }

    public byte[] aes_cbc_decrypt(Key key, byte[] c){
        byte[] result=null;
        try{
            byte[] iv=new byte[16];
            byte[] crypted=new byte[c.length-16];
            System.arraycopy(c, 0, iv, 0, iv.length);
            System.arraycopy(c, iv.length, crypted, 0, crypted.length);
            Cipher cipher=Cipher.getInstance("AES/CBC/PKCS7Padding", bc);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            result=cipher.doFinal(crypted);
        }catch(Exception e){
            System.out.println("Exception on cbc decrypt: ");
            e.printStackTrace();
        }
        return result;
    }

    public byte[] rsa_seg_encrypt(Key k, byte[] m){
        byte[] c = encrypt(m, k, "RSA/ECB/OAEPwithSHA1andMGF1Padding", bc);
        return c;
    }

    public byte[] rsa_seg_decrypt(Key k, byte[] c){
        byte[] m = decrypt(c, k, "RSA/ECB/OAEPwithSHA1andMGF1Padding", bc);
        return m;
    }

    public byte[] convertToken2Bytes(Token token){
        String str = token.getSubject() + (char)0x00 + token.getIssuer() + (char)0x00 + token.getTime() + (char)0x00 + token.getFSKey() + (char)0x00 + String.join("`", token.getGroups());
        return str.getBytes();
    }


        //RSA signature
    public byte[] sign(PrivateKey rsa_private, byte[] message){
        byte[] signed = null;
        try{
            Signature sig = Signature.getInstance("SHA256withRSA", "BC");
            sig.initSign(rsa_private, new SecureRandom());
            sig.update(message);
            signed=sig.sign();
        }
        catch(Exception e){
            System.out.println("Exception on RSA Key Generation: ");
            e.printStackTrace();
            System.exit(-1);
        }
        return signed;
    }
        
    public boolean verify(byte[] signed, PublicKey rsa_public, byte[] message){
        boolean verified = false;
        try{
            Signature sig = Signature.getInstance("SHA256withRSA", "BC");
            sig.initVerify(rsa_public);
            sig.update(message);
            verified = sig.verify(signed);
        }
        catch(Exception e){
            System.out.println("Exception on RSA Key Generation: ");
            e.printStackTrace();
            System.exit(-1);
        }
        return verified;
    }

    public static byte[] encrypt(byte[] text, Key key, String ec_mode, Provider p){
        byte[] result=null;
        try{
            Cipher cipher=Cipher.getInstance(ec_mode, p);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            result=cipher.doFinal(text);
        }catch(Exception e){
            System.out.println("Exception on encrypt: " + e);
            System.exit(-1);
        }
        return result;
    }

    public static byte[] decrypt(byte[] crypted, Key key, String dc_mode, Provider p){
        byte[] result=null;
        try{
            Cipher cipher=Cipher.getInstance(dc_mode, p);
            cipher.init(Cipher.DECRYPT_MODE, key);
            result=cipher.doFinal(crypted);
        }catch(Exception e){
            System.out.println("Exception on decrypt: " + e);
            System.exit(-1);
        }
        return result;
    }

    public static KeyPair gen_key_pair(int key_len){
        Crypto c1=new Crypto();
        KeyPair g_keys = c1.gen_RSAKey(key_len);
        PrivateKey private_key= g_keys.getPrivate();
        PublicKey public_key= g_keys.getPublic();
        byte[] key_str = public_key.getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(key_str);
        System.out.println("The public key: "+b64PublicKey);
        return g_keys;
    }
	
	public static byte[] objectToByteArray(Object obj) 
	{
        byte[] bytes = null;
        ByteArrayOutputStream byteArrayOutputStream = null;
        ObjectOutputStream objectOutputStream = null;
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(obj);
            objectOutputStream.flush();
            bytes = byteArrayOutputStream.toByteArray();

        } catch (IOException e) {
			e.printStackTrace();
        } 
        return bytes;
    }
	public static Object byteArrayToObject(byte[] bytes) 
	{
        Object obj = null;
        ByteArrayInputStream byteArrayInputStream = null;
        ObjectInputStream objectInputStream = null;
        try {
            byteArrayInputStream = new ByteArrayInputStream(bytes);
            objectInputStream = new ObjectInputStream(byteArrayInputStream);
            obj = objectInputStream.readObject();
        } catch (Exception e) {
			e.printStackTrace();
        } 
        return obj;
    }

    public byte[] rsa_sign_obj(Object obj, PrivateKey k){
        byte[] ba = objectToByteArray(obj);
        byte[] signature = sign(k, ba);
        return signature;
    }

    public boolean rsa_verify_sig(byte[] sig, PublicKey p, Object original){
        byte[] ba = objectToByteArray(original);
        boolean verified = verify(sig, p, ba);
        return verified;
    }

    public byte[] rsa_sign_token(Token token, PrivateKey k){
        byte[] ba = convertToken2Bytes(token);
        byte[] signature = sign(k, ba);
        return signature;
    }

    public boolean rsa_verify_sig_token(byte[] sig, PublicKey p, Token token){
        byte[] ba = convertToken2Bytes(token);
        boolean verified = verify(sig, p, ba);
        return verified;
    }

    public byte[] aes_encrypt_obj(Object obj, Key k){
        byte[] ba = objectToByteArray(obj);
        byte[] result = aes_cbc_encrypt(k, ba);
        return result;
    }

    public Object aes_decrypt_obj(byte[] c, Key k){
        byte[] ba = aes_cbc_decrypt(k, c);
        Object obj = byteArrayToObject(ba);
        return obj;
    }

    public byte[] rsa_encrypt_obj(Object obj, PublicKey k){
        byte[] ba = objectToByteArray(obj);
        byte[] result = encrypt(ba, k, "RSA/ECB/OAEPwithSHA1andMGF1Padding", bc);
        return result;
    }

    public Object rsa_decrypt_obj(byte[] c, PrivateKey k){
        byte[] ba = decrypt(c, k, "RSA/ECB/OAEPwithSHA1andMGF1Padding", bc);
        Object obj = byteArrayToObject(ba);
        return obj;
    }

	
	public byte[] hmac(byte[] result, byte[] hKey){
		SecretKey key = new SecretKeySpec(hKey, "HmacSHA256");
		byte [] encrypted = null;
		try
		{
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			mac.update(result);
			encrypted = mac.doFinal();
		}catch(Exception e){System.out.println("error" + e);}
		// System.out.println("result " + Base64.getEncoder().encodeToString(result));
		// System.out.println("hKey " + Base64.getEncoder().encodeToString(hKey));
		// System.out.println("encrypted " + Base64.getEncoder().encodeToString(encrypted));
		return encrypted;
	}

	public byte[] hmacKey(BigInteger sharedSecret){
		BigInteger padding = new BigInteger("666");
		BigInteger key = sharedSecret.add(padding);
		byte[] messageDigest = null;
		try{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		messageDigest = md.digest(key.toByteArray());
		}catch(Exception e){e.printStackTrace();}
		return messageDigest;
	}
	
	public static byte[] hmacKeyA(byte[] messagedigest){
		byte[] messageDigest = null;
		try{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		System.out.println("SSSSSSSSSSSSSHAR ED SECREAT   " + Base64.getEncoder().encodeToString(messagedigest));
		messageDigest = md.digest(messagedigest);
		}catch(Exception e){e.printStackTrace();}
		return messageDigest;
	}
	
	public byte[] encrypt_aes_hmac(Object obj, Key k, byte[] hKey){
		byte[] resultAes = aes_encrypt_obj(obj, k);
		byte[] hmac = hmac(resultAes, hKey);
		ArrayList<byte[]> message = new ArrayList<byte[]>();
		message.add(resultAes);
		message.add(hmac);
		return objectToByteArray(message);
	} 
	
	public byte[] decrypt_aes_hmac(byte[] BResponse, byte[] hKey)
	{
	    ArrayList<byte[]> result = (ArrayList)byteArrayToObject(BResponse);
		byte[] hmacThread = result.get(1);
		byte[] hmacClient = hmac(result.get(0), hKey);
		if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
		{
			System.out.println("The HMAC from the Client is not the same as the Server");
			System.exit(0);
		}
		return result.get(0);
	}
	


    public KeyPair gen_DH_keypair(){
        BigInteger g_ = new BigInteger(g, 16);
        BigInteger p_ = new BigInteger(N, 16);
        try {
            DHParameterSpec sp = new DHParameterSpec(p_, g_);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
            keyGen.initialize(sp);
            KeyPair pair = keyGen.generateKeyPair();
            return pair;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public KeyAgreement gen_DH_Agreement(KeyPair pair){
        try {
            KeyAgreement ag = KeyAgreement.getInstance("DH", "BC");
            ag.init(pair.getPrivate());
            return ag;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey gen_DH_Key(PublicKey puk, KeyAgreement ag) {
        try {
            ag.doPhase(puk, true);
            //256 key bit workaround
            byte[] secret = ag.generateSecret();
            SecretKey key = new SecretKeySpec(secret, 0, 32, "AES");
            return key;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
	
	public static byte[] DHH_Key(PublicKey puk, KeyAgreement ag) {
        try {
            ag.doPhase(puk, true);
            //256 key bit workaround
            byte[] secret = ag.generateSecret();
			byte[] result = hmacKeyA(secret);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}



