import java.util.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import javax.crypto.*;

public class MyApp{

	//The Client App

    private static FileClient fc;
    private static GroupClient gc;
    private static Scanner sc;


	public static void main(String args[]){

		fc=new FileClient();
		gc=new GroupClient();
    	System.out.println("Welcome to Client of FileSharing System.");
    	//Conncet to group server and file server
    	try{
			Scanner scan = new Scanner(System.in);
			System.out.print("Please enter the GroupServer's host name: ");
			String GHostName = scan.nextLine(); 
			System.out.print("Please enter the FileServer's host name: ");
			String FHostName = scan.nextLine(); 
			try{
				gc.connect(GHostName, 8765);
				fc.connect(FHostName, 4321);
			}catch(Exception e){
				System.out.println("The host name is wrong");
				System.exit(-1);
			}
			
    	}
    	catch(Exception e){
    		System.err.println("MyApp Failed to connect error: " + e.getMessage());
		    e.printStackTrace(System.err);
		    System.exit(0);
    	}

    	//check Usertoken
    	String username=null;
    	String password=null;
    	UserToken token=null;
    	String f_public_key=null;
    	sc = new Scanner(System.in);
    	while(token==null){
    		if(username!=null){
    			System.out.println("Username not found. Please re-enter.");
    		}
    		System.out.print("Please enter username :");
	    	username = sc.nextLine();
			System.out.print("Please enter your password: ");
			password = sc.nextLine();
			
			//check SRP
			if(gc.clientSRP(username, password) == false){
				System.out.println("SRP verification has failed...");
				System.out.println("Exiting...");
				System.exit(-1);
			}
			f_public_key = fc.getKey();
			if(f_public_key == null)
				System.exit(-1);
			ArrayList<Object> temp = gc.getToken(username, f_public_key);
	    	token = (UserToken)temp.get(0);
			byte[] signature = (byte[])temp.get(1);
			boolean atf = fc.authenticate(token, signature);
			if(!atf)
				System.exit(-1);
    	}

    	//print manual
    	System.out.print("Welcome, "+username + ". ");
    	String choice;
    	String tmp;
    	int level=0;

    	while(true){
			ArrayList<Object> temp = gc.getToken(username, f_public_key);
    		token = (UserToken)temp.get(0);
    		
    		//print options
    		System.out.println("This is the manual: ");
    		System.out.print(
    			"0. List all joined Groups\n"+
    			"1. List all owned Groups\n"+
    			"2. Create new group\n"+
    			"3. Delete group\n"+
    			"4. Upload files\n"+
    			"5. Download files\n"+
    			"6. Delete files\n"+
    			"7. List members\n"+
				"8. Add user to a group\n"+
				"9. Remove user from a group\n"+
				"10. List all files\n"
				);

    		if(token.getGroups().contains("ADMIN")){
    			level=-1;
    			System.out.print(
    			"A. Add new User\n"+
    			"R. Remove Users\n"
    			);
    		}
    		System.out.println("Q. Quit");
    		System.out.print("Please enter your choice >>");

    		//read input and call corresponding method
    		choice=sc.nextLine();
    		if(choice.equals("0")){
    			list_joined_groups(token);
    		}
    		else if(choice.equals("1")){
    			list_owned_groups(token);
    		}
    		else if(choice.equals("2")){
    			create_group(token);
    		}
    		else if(choice.equals("3")){
    			delete_group(token);
    		}
    		else if(choice.equals("4")){
    			upload_file(token);
    		}
    		else if(choice.equals("5")){
    			download_file(token);
    		}
    		else if(choice.equals("6")){
    			delete_file(token);
    		}
    		else if(choice.equals("7")){
    			list_members(token);
    		}
			else if(choice.equals("8")){
				add_user_to_group(token);
			}
			else if(choice.equals("9")){
				delete_user_from_group(token);
			}
			else if(choice.equals("10")){
				list_files(token);
			}
    		else if(choice.equals("Q")||choice.equals("q")){
    			System.exit(0);
    		}
    		else if(level==-1 && (choice.equals("A")||choice.equals("a"))){
    			create_user(token);
    		}
    		else if(level==-1 && (choice.equals("R")||choice.equals("r"))){
    			delete_user(token);
    		}
    		else{
    			System.out.println("Invalid input, please re-enter.");
    		}

    		System.out.println("\n\n****************************************\n\n");
    		System.out.println("Here are the options >>");
    	}


	}
	
	
	
	
	
	private static void list_files(UserToken u){
		List<String> list = fc.listFiles(u);
		if(list==null)
			System.out.println("File Not Found!");
		else if(list.isEmpty())
			System.out.println("There is no file in this group.");
		else
		{
			System.out.println(list.size() + " Files:");
			for(String file : list)
				System.out.println(file);
		}
	}

	private static boolean upload_file(UserToken u){
		String src, dst, grp;
		System.out.print("Please enter path of source file >>");
		src=sc.nextLine();
		System.out.print("Please enter path of destination >>");
		dst=sc.nextLine();
		System.out.print("Please enter group name >>");
		grp=sc.nextLine();

		ArrayList<SecretKey> groupKeys = gc.getGroupKeys(grp, u);
		
        boolean suc=fc.uploadEncryptedFile(src, dst, grp, u, groupKeys);
		// boolean suc=fc.upload(src, dst, grp, u);
		if(suc){
			System.out.println("Upload successful!");
		}
		else{
			System.out.println("Upload failed!");
		}
		return suc;
	}

	private static boolean download_file(UserToken u){
		String src, dst, grp;
		System.out.print("Please enter path of source file >>");
		src=sc.nextLine();
		System.out.print("Please enter path of destination >>");
		dst=sc.nextLine();
		System.out.print("Please enter group name >>");
		grp=sc.nextLine();
        // boolean suc=fc.download(src, dst, u);
		
		ArrayList<SecretKey> groupKeys = gc.getGroupKeys(grp, u);
		
		boolean suc = fc.downloadAndDecryptFile(src, dst, u, groupKeys);
		if(suc){
			System.out.println("Download successful!");
		}
		else{
			System.out.println("Download failed!");
		}
		return suc;
	}

	private static boolean delete_file(UserToken u){
		String src;
		System.out.print("Please enter path of source file >>");
		src=sc.nextLine();
		boolean suc=fc.delete(src, u);
		if(suc){
			System.out.println("Delete successful!");
		}
		else{
			System.out.println("Delete failed!");
		}
		return suc;
	}

	private static boolean create_group(UserToken u){
		String gn;
		System.out.print("Please enter groupname for new group >>");
		gn=sc.nextLine();
		boolean suc=gc.createGroup(gn, u);
		if(suc){
			System.out.println("Create Group "+gn+" successful!");
		}
		else{
			System.out.println("Create Group "+gn+" failed!");
		}
		return suc;
	}

	private static boolean delete_group(UserToken u){
		String gn;
		System.out.print("Please enter groupname for deletion >>");
		gn=sc.nextLine();
		boolean suc=gc.deleteGroup(gn, u);
		if(suc){
			System.out.println("Delete Group "+gn+" successful!");
		}
		else{
			System.out.println("Delete Group "+gn+" failed!");
		}
		return suc;
	}

	private static boolean create_user(UserToken u){
		String un; String pw;
		System.out.print("Please enter username for new user >>");
		un=sc.nextLine();
		//need to enter password and store W(password) in userlist
		System.out.print("Please enter password for new user >>");
		pw=sc.nextLine();
		boolean suc=gc.createUser(un,pw ,u);
		if(suc){
			System.out.println("Create User "+un+" successful!");
		}
		else{
			System.out.println("Create User "+un+" failed!");
		}
		return suc;
	}

	private static boolean delete_user(UserToken u){
		String un;
		System.out.print("Please enter username delete >>");
		un=sc.nextLine();
		boolean suc=gc.deleteUser(un, u);
		if(suc){
			System.out.println("Delete User "+un+" successful!");
		}
		else{
			System.out.println("Delete User "+un+" failed!");
		}
		return suc;
	}

	private static boolean add_user_to_group(UserToken u){
		System.out.print("Please enter the username: "); 
		String username = sc.nextLine();
		System.out.print("Please enter the group name: ");
		String groupname = sc.nextLine();
		boolean suc = gc.addUserToGroup(username,groupname,u);
		if(suc){
			System.out.println("User " + username + " is successfully added in group " + groupname +"!" );
		} else{
			System.out.println("Failed to add user to "+groupname);
		}
		return suc; 
	}

	private static boolean delete_user_from_group(UserToken u){
		System.out.print("Please enter the username: "); 
		String username = sc.nextLine();
		System.out.print("Please enter the group name: ");
		String groupname = sc.nextLine();
		boolean suc = gc.deleteUserFromGroup(username,groupname,u);
		if(suc){
			System.out.println("User " + username + " is successfully deleted from group " + groupname +"!" );
		} else{
			System.out.println("Failed!");
		}
		return suc; 
	}

	private static void list_members(UserToken u){
		System.out.print("Please enter the group name: ");
		String groupname = sc.nextLine();
		List<String> list = gc.listMembers(groupname,u);
		if(list==null){
			System.out.println("Group Not Found!");
		}
		else if(list.isEmpty()){
			System.out.println("There are no members in the group yet");
		}else{
			for(String member : list){
				System.out.println(member);
			}
		}
	}

	private static void list_joined_groups(UserToken u){
		System.out.print("Please enter the username: ");
		String username = sc.nextLine();
		List<String> list = gc.listGroups(username,u);
		if(list==null || list.isEmpty()){
			System.out.println("You haven't joined any groups");
		}else{
			for(String member : list){
				System.out.println(member);
			}
		}
	}

	private static void list_owned_groups(UserToken u){
		System.out.print("Please enter the username: ");
		String username = sc.nextLine();
		List<String> list = gc.listOwnedGroups(username,u);
		if(list==null || list.isEmpty()){
			System.out.println("You do not own any groups");
		}else{
			for(String member : list){
				System.out.println(member);
			}
		}
	}

	
}
