import java.util.*;
import java.sql.Timestamp;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.  
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
 
 
public class Token implements UserToken,java.io.Serializable{

    private String subject;
    private String issuer;
    private List<String> groups;
	private String time;
    private String fs_key;
	
    public Token(String issuer, String subject, List<String> groups, String fs_pk){
        this.issuer = issuer;
		this.subject = subject;
		this.groups = groups;
		Timestamp ts= new Timestamp(System.currentTimeMillis());
		this.time = ts.toString();
        this.fs_key = fs_pk;
    }
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer(){
        return issuer;
    }


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject(){
        return subject;
    }


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups(){
        return groups;
    }

    public String getTime(){
        return time;
    }

    public String getFSKey(){
        return fs_key;
    }

}   