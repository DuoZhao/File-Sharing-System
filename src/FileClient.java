/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.math.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.spec.SecretKeySpec;
//


public class FileClient extends Client implements FileClientInterface {

	Crypto crypto;
	SecretKey symmetricKey;
	SecretKey sessionKey;
	PublicKey publicKey; 
	byte[] hKey;

	public FileClient(){
		crypto = new Crypto();
		symmetricKey = crypto.gen_AESKey();
		// hKey = crypto.hmacKeyA(symmetricKey.getEncoded());
		publicKey = null;
		sessionKey = null;
	}

	public String getKey(){
		try{
			Envelope message = null, e = null;
			//Tell the server to return the member list
			message = new Envelope("GETKEY");

			this.sequence++;
			message.setSequence(this.sequence);
			output.writeObject(message);  	
			
			e = (Envelope)input.readObject();
			this.sequence++;
			if(e.getSequence() != this.sequence){
				System.out.println("Invalid sequence number");
				sock.close();
				disconnect();
			}
			//If server indicates success, return the member list			
			if(e.getMessage().equals("OK"))
			{ 
				publicKey = (PublicKey)e.getObjContents().get(0);
				byte[] key_str = publicKey.getEncoded();
				String b64PublicKey = Base64.getEncoder().encodeToString(key_str);
				System.out.println("The public key: "+b64PublicKey);
				System.out.print("Do you want to join this FileServer?(Y/N) ");
				Scanner kbd = new Scanner(System.in);
				String YN = kbd.nextLine();
				if(YN.equals("Y"))
					return b64PublicKey;
				else if(YN.equals("N"))
					return null;
			}	 
		}
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		return null;
	}

	public boolean authenticate(UserToken tk, byte[] signature){
		try{
			Envelope message = null, e = null;

			// Generate Diffie Hellman key
			KeyPair pair = crypto.gen_DH_keypair();
			KeyAgreement e1 = crypto.gen_DH_Agreement(pair);

			//Tell the server to return time stamp
			Timestamp ts= new Timestamp(System.currentTimeMillis());
			ArrayList<Object> pack = new ArrayList<Object>();
			pack.add(tk);
			pack.add(signature);
			pack.add(ts);
			pack.add(pair.getPublic());
			byte[] pack_arr = crypto.aes_encrypt_obj(pack, symmetricKey);
			byte[] key_arr = crypto.rsa_encrypt_obj(symmetricKey, publicKey);
			message = new Envelope("AUTH_USER_SERVER");
			message.addObject(pack_arr);
			message.addObject(key_arr);
			this.sequence++;
			message.setSequence(this.sequence);
			output.writeObject(message);  

			//read response
			byte[] ec = (byte[])input.readObject();
			e = (Envelope)crypto.aes_decrypt_obj(ec, symmetricKey);
			this.sequence++;
			if(e.getSequence() != this.sequence){
				System.out.println("Invalid sequence number");
				sock.close();
				disconnect();
			}
			
			//If server indicates success, return the member list
			if(e.getMessage().equals("OK"))
			{
				Timestamp newts = new Timestamp(ts.getTime() + 1);
				ArrayList<Object> tempList = e.getObjContents();
				if(newts.equals(tempList.get(0))){
					PublicKey pu2 = (PublicKey)tempList.get(1);
					symmetricKey = crypto.gen_DH_Key(pu2, e1);
					hKey = crypto.hmacKeyA(symmetricKey.getEncoded());
					System.out.println("symmetricKey encode  " + symmetricKey.getEncoded());
					return true;
				}
			}	
			System.out.println("There is a error on the authentication of fileserver!");
			return false;	 
		}
		catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    try {

			this.sequence++;
			env.setSequence(this.sequence);
			output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
			env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
		    this.sequence++;
			if(env.getSequence() != this.sequence){
				System.out.println("Invalid sequence number");
				sock.close();
				disconnect();
			}
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
						
						output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
					    // output.writeObject(crypto.aes_encrypt_obj((Object)env, symmetricKey));
						env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
						// env = (Envelope)crypto.aes_decrypt_obj((byte[])input.readObject(), symmetricKey);
					
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
								// output.writeObject(crypto.aes_encrypt_obj((Object)env, symmetricKey));
								env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
								// env = (Envelope)crypto.aes_decrypt_obj((byte[])input.readObject(), symmetricKey);							
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
								// output.writeObject(crypto.aes_encrypt_obj((Object)env, symmetricKey));
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token

			 this.sequence++;
			 message.setSequence(this.sequence);
			 output.writeObject(crypto.encrypt_aes_hmac((Object)message, symmetricKey, hKey));
			 
			 e = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
			 this.sequence++;
			 if(e.getSequence() != this.sequence){
				System.out.println("Invalid sequence number");
				sock.close();
				disconnect();
			 }
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }		
		try
		 { 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 output.writeObject(crypto.encrypt_aes_hmac((Object)message, symmetricKey, hKey));
			 // output.writeObject(crypto.aes_encrypt_obj(message, symmetricKey));
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
			 // env = (Envelope)crypto.aes_decrypt_obj((byte[])input.readObject(), symmetricKey);
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					
					output.writeObject(crypto.encrypt_aes_hmac((Object)message, symmetricKey, hKey));
					// output.writeObject(crypto.aes_encrypt_obj((Object)message, symmetricKey));
					
					env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
					// env = (Envelope)crypto.aes_decrypt_obj((byte[])input.readObject(), symmetricKey);
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				message = new Envelope("EOF");
				output.writeObject(crypto.encrypt_aes_hmac((Object)message, symmetricKey, hKey));
				// output.writeObject(crypto.aes_encrypt_obj((Object)message, symmetricKey));
				env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
				// env = (Envelope)crypto.aes_decrypt_obj((byte[])input.readObject(), symmetricKey);
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}
	
	public boolean uploadEncryptedFile(String sourceFile, String destFile, String group,
			UserToken token, ArrayList<SecretKey> groupKeys) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		try
		 {
			 Envelope message = null, env = null;
			 int versionOfKey = groupKeys.size() - 1;
			 
			 System.out.println("version of the group key: " + versionOfKey);
			 
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 message.addObject(Integer.valueOf(versionOfKey));
			 
			 this.sequence++;
			 message.setSequence(sequence);
			 output.writeObject(crypto.encrypt_aes_hmac((Object)message, symmetricKey, hKey));
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			
			 env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
			 this.sequence++;
			 if(env.getSequence() != this.sequence){
				 System.out.println("Invalid sequence number");
				 sock.close();
				 disconnect();
			 }
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					//create a byte array that fit the data
					byte[] temp = new byte[n];
					System.arraycopy(buf, 0, temp, 0, n);
					//encrypt the file
					//In Crypto.java, AES encrypt use first 16 bytes for iv
					SecretKey key = groupKeys.get(versionOfKey);
					temp = crypto.aes_cbc_encrypt(key, temp);
					
					// System.out.println("n length: " + n);
					// System.out.println("temp length: " + temp.length);
					
					message.addObject(temp);
					//take care of padding of the last block
					message.addObject(temp.length);
				
					this.sequence++;
					message.setSequence(sequence);
					output.writeObject(crypto.encrypt_aes_hmac((Object)message, symmetricKey, hKey));
					
					
					env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
					this.sequence++;
					if(env.getSequence() != this.sequence){
						System.out.println("Invalid sequence number");
						sock.close();
						disconnect();
					}
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
			
				message = new Envelope("EOF");
				
				this.sequence++;
				message.setSequence(this.sequence);
				output.writeObject(crypto.encrypt_aes_hmac((Object)message, symmetricKey, hKey));
					
				env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
				this.sequence++;
				if(env.getSequence() != this.sequence){
					System.out.println("Invalid sequence number");
					sock.close();
					disconnect();
				}
				
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}
	
	public boolean downloadAndDecryptFile(String sourceFile, String destFile, UserToken token, ArrayList<SecretKey> groupKeys) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
					
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
						
						this.sequence++;
						env.setSequence(this.sequence);
					    output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
						
						SecretKey key = null; 
						env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
						this.sequence++;
						if(env.getSequence() != this.sequence){
							System.out.println("Invalid sequence number");
							sock.close();
							disconnect();
						}
						
						if(env.getMessage().compareTo("VERSIONOFKEY")==0){
							int versionOfKey = (Integer) env.getObjContents().get(0);
							
							System.out.println("version of the group key: " + versionOfKey);
							
							key = groupKeys.get(versionOfKey);
							env = new Envelope("DOWNLOADF");
							this.sequence++;
							env.setSequence(this.sequence);
							output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
						}
					
						env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
						this.sequence++;
						if(env.getSequence() != this.sequence){
							System.out.println("Invalid sequence number");
							sock.close();
							disconnect();
						}
						
						while (env.getMessage().compareTo("CHUNK")==0) { 
								//get the buf and key to decrypt. After, write it to the dest file
								byte[] buf = (byte[])env.getObjContents().get(0);
								buf = crypto.aes_cbc_decrypt(key, buf);		//modify------
							
								//the only problem, the last block should be the actual size, not 4096 bytes. 
								// System.out.println("Decrypt Buf length: " + buf.length);
								
								fos.write(buf, 0, buf.length);
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								
								this.sequence++;
								env.setSequence(this.sequence);
								output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
								env = (Envelope)crypto.aes_decrypt_obj(crypto.decrypt_aes_hmac((byte[])input.readObject(), hKey), symmetricKey);
								this.sequence++;
								if(env.getSequence() != this.sequence){
									System.out.println("Invalid sequence number");
									sock.close();
									disconnect();
								}
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								
								this.sequence++;
								env.setSequence(this.sequence);
								output.writeObject(crypto.encrypt_aes_hmac((Object)env, symmetricKey, hKey));
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

}

