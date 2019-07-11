/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.*;
import java.math.*;
import java.sql.Timestamp;
import java.util.ArrayList;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class FileThread extends Thread
{
	private final Socket socket;
	private final KeyPair fs_key;
	private final PublicKey gs_key;
	private final Crypto crypto;
	private Key ses_key;
	private byte[] hKey;
	private Timestamp last_ts;
	private boolean start_channel;
	private int sequence = 0;

	public FileThread(Socket _socket, KeyPair fs, PublicKey gs)
	{
		socket = _socket;
		fs_key = fs;
		gs_key = gs;
		crypto = new Crypto();
		last_ts = null;
		ses_key = null;
		start_channel = false;
	}

	@SuppressWarnings("unchecked")
	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope e;
				byte[] tmp_arr = null;
				if(!start_channel){
					e = (Envelope)input.readObject();
					this.sequence++;
					if(e.getSequence() != this.sequence){
						System.out.println("Invalid sequence number");
						socket.close();
						proceed = false;
					}
				}
				else{
					tmp_arr = (byte[])input.readObject();

					ArrayList<byte[]> result = (ArrayList)crypto.byteArrayToObject(tmp_arr);
					byte[] hmacClient = result.get(1);
					byte[] hmacThread = crypto.hmac(result.get(0), hKey);
					if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
					{
						System.out.println("The HMAC from the Client is not the same as the Server");
						socket.close();
					}
					e = (Envelope)crypto.aes_decrypt_obj(result.get(0), ses_key);

			
					this.sequence++;
					if(e.getSequence() != this.sequence){
						System.out.println("Invalid sequence number");
						socket.close();
						proceed = false;
					}
				}
				System.out.println("Request received: " + e.getMessage());

				if(e.getMessage().equals("GETKEY")){
					response = new Envelope("OK");
                    response.addObject(fs_key.getPublic());
					this.sequence++;
					response.setSequence(this.sequence);
                    output.writeObject(response);
				}

				//Handler to authenticate user
				else if(e.getMessage().equals("AUTH_USER_SERVER")){
					Key temp_key = null;
				    if(e.getObjContents().size() < 2 || e.getObjContents().get(0) == null){
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else{
						//get message content
						ArrayList<Object> tempArrayList = e.getObjContents();
						byte[] pack_arr = (byte[])tempArrayList.get(0);
						byte[] key_arr= (byte[])tempArrayList.get(1);

						//get temp key
						temp_key = (Key)crypto.rsa_decrypt_obj(key_arr, fs_key.getPrivate());

						//get pack message
						ArrayList<Object> pack = (ArrayList<Object>)crypto.aes_decrypt_obj(pack_arr, temp_key);
						UserToken yourToken = (UserToken)pack.get(0);
						byte[] token_sig = (byte[])pack.get(1);
						Timestamp ts = (Timestamp)pack.get(2);


						Timestamp sig_ts = Timestamp.valueOf(((Token)yourToken).getTime());
						Timestamp n_30_min = new Timestamp(System.currentTimeMillis() - 30 * 60 * 1000);
						Timestamp n_20_sec = new Timestamp(System.currentTimeMillis() - 20 * 1000);

						byte[] key_str = fs_key.getPublic().getEncoded();
						String b64PublicKey = Base64.getEncoder().encodeToString(key_str);
						String token_key = ((Token)yourToken).getFSKey();
						if(ts==null || ts.before(n_20_sec) || (last_ts!=null && (ts.equals(last_ts) || ts.before(last_ts)))){
							response = new Envelope("BAD-Timestamp");
							System.out.println("bad Timestamp!");
						}
						else if(!crypto.rsa_verify_sig_token(token_sig, gs_key, (Token)yourToken)){
							response = new Envelope("BAD-SIGNATURE");
							System.out.println("bad signature!");
						}
						else if(sig_ts == null || sig_ts.before(n_30_min)){
							response = new Envelope("OLD-SIGNATURE");
							System.out.println("old invalid signature!");
						}
						else if(!b64PublicKey.equals(token_key)){
							response = new Envelope("WRONG-PUBLIC-KEY");
							System.out.println("invalid destination!");
						}
						else{
							//generate key pair
							PublicKey publickey_c = (PublicKey)pack.get(3);
							KeyPair pair = crypto.gen_DH_keypair();
							KeyAgreement e2 = crypto.gen_DH_Agreement(pair);
							ses_key = crypto.gen_DH_Key(publickey_c, e2);
							System.out.println("ses_key encode  " + ses_key.getEncoded());
							hKey = crypto.hmacKeyA(ses_key.getEncoded());


							last_ts = ts;
							Timestamp later = new Timestamp(ts.getTime() + 1);
							response = new Envelope("OK");
	                        response.addObject(later);
	                        response.addObject(pair.getPublic());
	                        start_channel = true;
	                    }
						this.sequence++;
						response.setSequence(this.sequence);
	                    output.writeObject(crypto.aes_encrypt_obj(response, temp_key));
					}
				}
				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    if(e.getObjContents().size() < 1 && e.getObjContents().get(0) == null)
					{
						System.out.println("Inside the if");
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						UserToken yourToken = (UserToken)e.getObjContents().get(0);
						List<String> grouplist = yourToken.getGroups();
						List<String> result = new ArrayList<String>();
						
						for(int i = 0 ; i < grouplist.size() ; i++)
						{
							for(int j = 0 ; j < FileServer.fileList.getFiles().size() ; j++)
							{								
								if(FileServer.fileList.getFiles().get(j).getGroup().equals(grouplist.get(i)))
								{
									result.add(FileServer.fileList.getFiles().get(j).getPath());
									System.out.println("Found file: " + FileServer.fileList.getFiles().get(j).getPath() + "  " + i + "  " + j);
									for(ShareFile file : FileServer.fileList.getFiles())
										System.out.println(file.getPath());
									for(String g: grouplist){
										System.out.println(g);
									}
								}
							}
							
						}
						response = new Envelope("OK");
                        response.addObject(result); 
					}
					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, ses_key, hKey));
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						if(e.getObjContents().get(3) == null) {
							response = new Envelope("FAIL-BADVERSION");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							int versionOfKey = (Integer)e.getObjContents().get(3);
							
							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success

								this.sequence++;
								response.setSequence(this.sequence);
								output.writeObject(crypto.encrypt_aes_hmac(response, ses_key, hKey));

								tmp_arr = (byte[])input.readObject();
								ArrayList<byte[]> result = (ArrayList)crypto.byteArrayToObject(tmp_arr);
								byte[] hmacClient = result.get(1);
								byte[] hmacThread = crypto.hmac(result.get(0), hKey);
								if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
								{
									System.out.println("The HMAC from the Client is not the same as the Server");
									socket.close();
								}
								e = (Envelope)crypto.aes_decrypt_obj(result.get(0), ses_key);
								this.sequence++;
								if(e.getSequence() != this.sequence){
									System.out.println("Invalid sequence number");
									socket.close();
									proceed = false;
								}
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									this.sequence++;
									response.setSequence(this.sequence);
									output.writeObject(crypto.encrypt_aes_hmac(response, ses_key, hKey));
									tmp_arr = (byte[])input.readObject();
									result = (ArrayList)crypto.byteArrayToObject(tmp_arr);
									hmacClient = result.get(1);
									hmacThread = crypto.hmac(result.get(0), hKey);
									if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
									{
										System.out.println("The HMAC from the Client is not the same as the Server");
										socket.close();
									}
									e = (Envelope)crypto.aes_decrypt_obj(result.get(0), ses_key);
									this.sequence++;
									if(e.getSequence() != this.sequence){
										System.out.println("Invalid sequence number");
										socket.close();
										proceed = false;
									}
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, versionOfKey);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, ses_key, hKey));
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");

						this.sequence++;
						e.setSequence(this.sequence);
						output.writeObject(crypto.encrypt_aes_hmac(e, ses_key, hKey));
						output.reset();
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						this.sequence++;
						e.setSequence(this.sequence);
						output.writeObject(crypto.encrypt_aes_hmac(e, ses_key, hKey));

						output.reset();
					}
					else {
						//get version of key and send it to file client
						Integer versionOfKey = sf.getVersionOfKey();
						e = new Envelope("VERSIONOFKEY");
						e.addObject(versionOfKey);
						this.sequence++;
						e.setSequence(this.sequence);
						output.writeObject(crypto.encrypt_aes_hmac(e, ses_key, hKey));
						output.reset();
					
						tmp_arr = (byte[])input.readObject();
						// ????e = (Envelope)crypto.aes_decrypt_obj(tmp_arr, ses_key);
						ArrayList<byte[]> result = (ArrayList)crypto.byteArrayToObject(tmp_arr);
						byte[] hmacClient = result.get(1);
						byte[] hmacThread = crypto.hmac(result.get(0), hKey);
						if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
						{
							System.out.println("The HMAC from the Client is not the same as the Server");
							socket.close();
						}
						e = (Envelope)crypto.aes_decrypt_obj(result.get(0), ses_key);
						this.sequence++;
						if(e.getSequence() != this.sequence){
							System.out.println("Invalid sequence number");
							socket.close();
							proceed = false;
						}
					
						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");

							this.sequence++;
							e.setSequence(this.sequence);
							output.writeObject(crypto.encrypt_aes_hmac(e, ses_key, hKey));

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								//encrypt 4128 bytes, but decrypt 4096 bytes, so there will be errors
								byte[] buf = new byte[4128];	//modify-------
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}

									
								byte[] temp = new byte[n];
								System.arraycopy(buf, 0, temp, 0, n);
								
								e.addObject(temp);
								e.addObject(temp.length); //modify-------
								
								this.sequence++;
								e.setSequence(this.sequence);
								output.writeObject(crypto.encrypt_aes_hmac(e, ses_key, hKey));

								tmp_arr = (byte[])input.readObject();
								result = (ArrayList)crypto.byteArrayToObject(tmp_arr);/////////////////
								hmacClient = result.get(1); ////////////////////////////
								hmacThread = crypto.hmac(result.get(0), hKey); /////////////////////
								if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
								{
									System.out.println("The HMAC from the Client is not the same as the Server");
									socket.close();
								}
								e = (Envelope)crypto.aes_decrypt_obj(result.get(0), ses_key);
								
								this.sequence++;
								if(e.getSequence() != this.sequence){
									System.out.println("Invalid sequence number");
									socket.close();
									proceed = false;
								}

							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								this.sequence++;
								e.setSequence(this.sequence);
								output.writeObject(crypto.encrypt_aes_hmac(e, ses_key, hKey));

								tmp_arr = (byte[])input.readObject();
								result = (ArrayList)crypto.byteArrayToObject(tmp_arr);///////////////
								hmacClient = result.get(1);/////////////////////////
								hmacThread = crypto.hmac(result.get(0), hKey);///////////////
								if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
								{
									System.out.println("The HMAC from the Client is not the same as the Server");
									socket.close();
								}
								e = (Envelope)crypto.aes_decrypt_obj(result.get(0), ses_key);
								this.sequence++;
								if(e.getSequence() != this.sequence){
									System.out.println("Invalid sequence number");
									socket.close();
									proceed = false;
								}
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {
					output.reset();
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{
							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}

					this.sequence++;
					e.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(e, ses_key, hKey));

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
