import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class Question3 {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("HELLO");
		 try{
	            //set necessary keystore properties - using a p12 file
	            System.setProperty("javax.net.ssl.keyStore","client.jks");
	            System.setProperty("javax.net.ssl.keyStorePassword","client");
	            System.setProperty("javax.net.ssl.keyStoreType", "JKS");       
	            System.setProperty("java.protocol.handler.pkgs","com.sun.net.ssl.internal.www.protocol"); 
	            
	            //set necessary truststore properties - using JKS
	            System.setProperty("javax.net.ssl.trustStore","server.jks");
	            System.setProperty("javax.net.ssl.trustStorePassword","Server");
	            // register a https protocol handler  - this may be required for previous JDK versions
	            System.setProperty("java.protocol.handler.pkgs","com.sun.net.ssl.internal.www.protocol");
	            
	            //connect to google           
	            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();            
	            SSLSocket sslSock = (SSLSocket) factory.createSocket("mail.google.com",443);
	                       
	            //send HTTP get request
	            BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(sslSock.getOutputStream(), "UTF8"));            
	            wr.write("GET /mail HTTP/1.1\r\nhost: mail.google.com\r\n\r\n");
	            wr.flush();
	             
	            // read response
	            BufferedReader rd = new BufferedReader(new InputStreamReader(sslSock.getInputStream()));           
	            String string = null;

	            while ((string = rd.readLine()) != null) {
	                System.out.println(string);
	                System.out.flush();
	            }
	           
	            rd.close();
	            wr.close();
	            // Close connection.
	            sslSock.close();
	           
	        }catch(Exception ex){
	            System.out.println(ex.getMessage());
	        }
	    }
}
