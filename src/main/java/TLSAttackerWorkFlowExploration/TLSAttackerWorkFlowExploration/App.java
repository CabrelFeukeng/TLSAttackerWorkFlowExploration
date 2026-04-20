package TLSAttackerWorkFlowExploration.TLSAttackerWorkFlowExploration;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import config.GlobalConfig;
import config.OpenSSLServerConfig;
import config.TlsClientConfig;
import config.TlsClientConfigForTLS12;
import config.TlsClientConfigForTLS13;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import enums.TlsVersion;
import executer.TlsWorkflowExecutor;
import serverlauncher.OpenSSLServerLauncher;
import utils.MessageToJson;
import utils.TraceToString;
import workflow.TlsWorkflowBuilderForTLS13;
import workflow.TlsWorkflowBuilder;
import workflow.TlsWorkflowBuilderForTLS12;

public class App 
{

    public static void main( String[] args )
    {
    	String tlsVersion = "TLS13";
    	String ComType = "OK";
    	
    	// Variable à initialiser
    	OpenSSLServerConfig opensslServerConfig = null;
    	
        // Register BouncyCastle for crypto support
    	Security.insertProviderAt(new BouncyCastleProvider(), 1);
    	
    	// Get OpenSSL server default configuration
    	switch (tlsVersion) {
    	   case "TLS13" :
    		   switch (ComType) {
	    		   case "OK" :
	    			    opensslServerConfig = OpenSSLServerConfig
			    	    .builder()
			    		.version(TlsVersion.TLS_1_3)
			            .wwwArg(true)
			            .cipherSuites(GlobalConfig.TLS13ServerCipherSuitesOK)
			            .build();
	    			    break;
	    		   case "KO" :
	    			    opensslServerConfig = OpenSSLServerConfig
	   				    .builder()
	   		    		.version(TlsVersion.TLS_1_3)
	   		            .wwwArg(true)
	   		            .cipherSuites(GlobalConfig.TLS13ServerCipherSuitesKO)
	   		            .build();
	    			    break;
	    		   default :
	    			   opensslServerConfig = OpenSSLServerConfig
			    	    .builder()
			    		.version(TlsVersion.TLS_1_3)
			            .wwwArg(true)
			            .cipherSuites(GlobalConfig.TLS13ServerCipherSuitesOK)
			            .build();
	    			   break;
    		   }
    		   break;
    	   case "TLS12" :
    		   switch (ComType) {
	    		   case "OK" :
	    			    opensslServerConfig = OpenSSLServerConfig
			    	    .builder()
			    		.version(TlsVersion.TLS_1_2)
			            .wwwArg(true)
			            .cipherSuites(GlobalConfig.TLS12ServerCipherSuitesOK)
			            .build();
	    			    break;
	    		   case "KO" :
	    			    opensslServerConfig = OpenSSLServerConfig
	   				    .builder()
	   		    		.version(TlsVersion.TLS_1_2)
	   		            .wwwArg(true)
	   		            .cipherSuites(GlobalConfig.TLS12ServerCipherSuitesKO)
	   		            .build();
	    			    break;
	    		   default :
	    			   opensslServerConfig = OpenSSLServerConfig
			    	    .builder()
			    		.version(TlsVersion.TLS_1_2)
			            .wwwArg(true)
			            .cipherSuites(GlobalConfig.TLS12ServerCipherSuitesOK)
			            .build();
	    			   break;
    		   }
    		   break;
    	   default :
    		   // Configuration par défaut pour TLS 1.3
    		   opensslServerConfig = OpenSSLServerConfig
    			    .builder()
    				.version(TlsVersion.TLS_1_2)
    	            .wwwArg(true)
    	            .cipherSuites(GlobalConfig.TLS12ServerCipherSuitesOK)
    	            .build();
    		   break;
    	}
    	
    	// Vérifier que la configuration n'est pas null
    	if (opensslServerConfig == null) {
    		System.err.println("Error: OpenSSLServerConfig is null");
    		return;
    	}

        // Launch OpenSSL server with TLS default configuration
    	OpenSSLServerLauncher launcher = new OpenSSLServerLauncher(opensslServerConfig);
  
        try {
        	launcher.start();
        } catch (Exception e) {
            System.err.println("Unable to start OpenSSL server: " + e.getMessage());
            System.err.println("Make sure OpenSSL is installed: openssl version");
            return;
        }
        
        TlsClientConfig clientConfig = null;
        
        try {
        	
        	// Get TLS client configuration
        	switch (tlsVersion) {
        	   case "TLS13" :
        		  clientConfig = TlsClientConfigForTLS13.getInstance();
        		   switch (ComType) {
        		       case "OK" :
        	    		  clientConfig.setCipherSuites(GlobalConfig.TLS13ClientCipherSuitesOK);
        	    		  break;
        	    	    case "KO" :
        	    		  clientConfig.setCipherSuites(GlobalConfig.TLS13ClientCipherSuitesKO);
        	    		  break;
        	    	    default :
        	    		  clientConfig.setCipherSuites(GlobalConfig.TLS13ClientCipherSuitesOK);
        	    		  break;
        		   }
        		   break;
        	   case "TLS12" :
        		  // CORRECTION : Utiliser TlsClientConfigForTLS12 au lieu de TlsClientConfigForTLS13
        		  clientConfig = TlsClientConfigForTLS12.getInstance();
        		   switch (ComType) {
        		       case "OK" :
        	    		  clientConfig.setCipherSuites(GlobalConfig.TLS12ClientCipherSuitesOK);
        	    		  break;
        	    	    case "KO" :
        	    		  clientConfig.setCipherSuites(GlobalConfig.TLS12ClientCipherSuitesKO);
        	    		  break;
        	    	    default :
        	    		  clientConfig.setCipherSuites(GlobalConfig.TLS12ClientCipherSuitesOK);
        	    		  break;
        		   }
        		   break;
        	   default :
        		   // Configuration par défaut pour TLS 1.3
        		   clientConfig = TlsClientConfigForTLS13.getInstance();
        		   clientConfig.setCipherSuites(GlobalConfig.TLS13ClientCipherSuitesOK);
        		   break;
        	}

        	// Build workflow trace (ClientHello, receive ServerHello, etc.)
        	TlsWorkflowBuilder builder = tlsVersion.equals("TLS13")
        			? new TlsWorkflowBuilderForTLS13()
        		    : new TlsWorkflowBuilderForTLS12();
        	
            WorkflowTrace trace = builder.build(clientConfig);   

            // Execute handshake against OpenSSL server
            TlsWorkflowExecutor executor = new TlsWorkflowExecutor(clientConfig, trace);
            State state = executor.execute();
            
            // Export captured messages to JSON file
            MessageToJson mtj = new MessageToJson(state.getWorkflowTrace());
            mtj.informationsExtraction(tlsVersion);
            
            // Print human-readable trace to console
            System.out.println((new TraceToString(state.getWorkflowTrace())).toString());

        } finally {
        	// Always kill OpenSSL process
        	launcher.stop();
        }
    }
}