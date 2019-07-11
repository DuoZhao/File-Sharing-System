/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;

//for clientSRP()
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.digests.SHA256Digest;
import java.security.*;
import java.util.*;
import java.math.*;

public class GroupClient extends Client implements GroupClientInterface {

	//global variables 
	private static final BigInteger N = new BigInteger("e438f5f9e266d547f2ce63db4f2ccef46c4f2ebdac1a5eb703ae1ce9"+
					   "afae2100a2ea6922df52d6dbada5ff0c3dc510613275918b6a26b19f"+
					   "c1e5625e58c2a045492a2283da75ec38a9f0748c87b9db06d72c65bd"+
					   "ca21fdf3cc02ac48165d539996d7aa2f99b4a39d370cbaf0e4a07b77"+
					   "49899c3a5d73f54b792094857b3693d3",16);	
					   
	private static final BigInteger g = new BigInteger("c4a04391743a1a270af5bec952a84951229560b5a4b7ca1a24316836"+
					   "b9031943f4f2cb64aa854f7ca9546530ed11dce0f54691baec98b1c6"+
					   "a8de9b80ae96f684c0b84dfdcc505951a896ce3f4d07556e93f00dfd"+
					   "1c64a76c10721afb390ee2af5515fe40d1a0cb97c9eb9162da33981c"+
					   "d9260de4f6721b6421b243d39dc0c412",16);
		
	private SecretKey K;
	private byte[] hKey;
	private Crypto crypto = new Crypto();
	
	public boolean clientSRP (String username, String password){
		Security.addProvider(new BouncyCastleProvider());
		byte[] I = username.getBytes();
		byte[] P = password.getBytes();
		byte[] s = getSalt(username);
		
		SRP6Client client = new SRP6Client();
		client.init(N, g, new SHA256Digest(), new SecureRandom());
		BigInteger A = client.generateClientCredentials(s, I, P);
		
		Envelope message = null, response = null;
		try{
			//client send ClientCredentials to server. 
			message = new Envelope("SRP");
			message.addObject(username);
			message.addObject(A);
			
			//sequence number
			this.sequence++;
			message.setSequence(this.sequence);
			output.writeObject(message);
			
			response = (Envelope)input.readObject();
			//check sequence number
			this.sequence++;
			if(this.sequence != response.getSequence()){
				System.out.println("Invalid sequence number");
				sock.close();	//close group client socket
				disconnect();	//close group thread socket
			}
		}catch(Exception e){
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		
		BigInteger S =null;  BigInteger B =null;
		try{
			B = (BigInteger)response.getObjContents().get(0);
			// *******************************************key
			S = client.calculateSecret(B);
			// *******************************************key
			// System.out.println("********************************");
			// System.out.println("GroupClient calcultae the secret: "+S.toString(16));
			// System.out.println("********************************");			
		} catch(CryptoException e){	
			System.out.println(e.getMessage());
		}		
		//K is a 128 bit SecretKey
		K = new SecretKeySpec(S.toByteArray(), 0, 32, "AES");
		// hKey is the hmacKey for doing hmac which is 256 bit
		hKey = crypto.hmacKey(S);
		byte[] c1 = (byte[]) response.getObjContents().get(1);
	
		return challengeResponse(c1);
		
	 }
	 
	 private byte[] getSalt(String username){
		 Envelope message = null, response = null;
		 message = new Envelope("SALT");
		 byte[] salt = null;
		 
		 try{
			 message.addObject(username);
			 //sequence number
			this.sequence++;
			message.setSequence(this.sequence);
			output.writeObject(message);
			
			response = (Envelope)input.readObject();
			//check sequence number
			this.sequence++;
			if(this.sequence != response.getSequence()){
				System.out.println("Invalid sequence number");
				sock.close();	//close group client socket
				disconnect();	//close group thread socket
			}
			 salt = (byte[])response.getObjContents().get(0);
		 }catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		return salt;
	 }
	
	public boolean challengeResponse(byte[] c1)
	{
		Envelope message = null, response = null;
		message = new Envelope("CHALLENGERES");	//challengeResponse
		
		//generate c2
		SecureRandom random = new SecureRandom();
		byte[] c2 = new byte[16];
		random.nextBytes(c2);
		
		Crypto crypto = new Crypto();
		try{
			message.addObject(crypto.aes_cbc_encrypt(K,c1));
			message.addObject(c2);
			//sequence number
			this.sequence++;
			message.setSequence(this.sequence);
			output.writeObject(message);
			
			response = (Envelope)input.readObject();
			//check sequence number
			this.sequence++;
			if(this.sequence != response.getSequence()){
				System.out.println("Invalid sequence number");
				sock.close();	//close group client socket
				disconnect();	//close group thread socket
			}
			
		}catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		byte[] c2_encrypt = (byte[]) response.getObjContents().get(0);
		byte[] c2_decrypt = crypto.aes_cbc_decrypt(K,c2_encrypt);
		return Arrays.equals(c2,c2_decrypt);
	}
	
	public ArrayList<Object> getToken(String username, String fs_key)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string

			message.addObject(fs_key);
			
			this.sequence++;
			message.setSequence(this.sequence);
			output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey));
		
			//Get the response from the server
			byte[] BResponse = (byte[])input.readObject();
			response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
			this.sequence++;
			if(response.getSequence() != this.sequence){
				System.out.println("Invalid sequence number");
				sock.close();
				disconnect();
			}
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 2)
					return temp;	
			}

			
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }
	 
	 public boolean createUser(String username, String password,UserToken token)
	 {
		 try
			{
				//password calculation 
				SecureRandom random = new SecureRandom();
				byte[] s =new byte[32];
				random.nextBytes(s);
				
				//server stores g^w mod N
				BigInteger w = SRP6Util.calculateX(new SHA256Digest(),N,s,username.getBytes(),password.getBytes());
				BigInteger v = g.modPow(w,N);
				
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(v);//Add passwordmod 
				message.addObject(s);//Add salt
				message.addObject(token); //Add the requester's token

				
				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey));
			
				byte[] BResponse = (byte[])input.readObject();
				response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}

				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token

				
				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey));
			
				byte[] BResponse = (byte[])input.readObject();
				response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token

				
				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey)); 
			
				byte[] BResponse = (byte[])input.readObject();
				response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey)); 
			
				byte[] BResponse = (byte[])input.readObject();
				response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token

			 
			this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey)); 
			 
		     	byte[] BResponse = (byte[])input.readObject();
		     	response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	 public List<String> listGroups(String username, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LGROUPS");
			 message.addObject(username); //Add group name string
			 message.addObject(token); //Add requester's token

		
			this.sequence++;
			message.setSequence(this.sequence);
			output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey)); 
		 
		 	byte[] BResponse = (byte[])input.readObject();
		 	response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
			this.sequence++;
			if(response.getSequence() != this.sequence){
				System.out.println("Invalid sequence number");
				sock.close();
				disconnect();
			}
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }


	 @SuppressWarnings("unchecked")
	 public List<String> listOwnedGroups(String username, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LOWNEDGROUPS");
			 message.addObject(username); //Add group name string
			 message.addObject(token); //Add requester's token

			
				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey)); 
			 
			 	byte[] BResponse = (byte[])input.readObject();
			 	response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

				
				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey)); 
			
				byte[] BResponse = (byte[])input.readObject();
				response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token

				
				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey));
			
				byte[] BResponse = (byte[])input.readObject();
				response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	 public ArrayList<SecretKey> getGroupKeys(String groupname, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("GETGROUPKEYS");
			 message.addObject(groupname); //Add group name string
			 message.addObject(token); //Add requester's token
			
			this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac(message, K, hKey));
		
				//Get the response from the server
				byte[] BResponse = (byte[])input.readObject();
				response = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac(BResponse, hKey), K);
				this.sequence++;
				if(response.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (ArrayList<SecretKey>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

}
