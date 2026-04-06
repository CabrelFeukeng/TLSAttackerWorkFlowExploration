package executer;


import config.TlsClientConfigForTLS12;
import config.TlsClientConfigForTLS13;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TlsWorkflowExecutor {

	 private static final Logger LOG = LoggerFactory.getLogger(TlsWorkflowExecutor.class);

	 private final TlsClientConfigForTLS12 clientConfig12 = TlsClientConfigForTLS12.getInstance();
	 private final TlsClientConfigForTLS13 clientConfig13 = TlsClientConfigForTLS13.getInstance();
	 
	 private static TlsWorkflowExecutor instance;
	 
	 private TlsWorkflowExecutor() {} 
	    
	 public static TlsWorkflowExecutor getInstance() {
	        if (instance == null) {
	            instance = new TlsWorkflowExecutor();
	        }
	        return instance;
	 }
	 
	 public State execute(WorkflowTrace trace, String tlsVersion) {

		    Config config = resolveConfig(tlsVersion);
		    if (config == null) {
		        LOG.error("Version TLS non supportée : '{}'. Versions acceptées : TLS_12, TLS_13", tlsVersion);
		        return null;
		    }
		    
		    State state = new State(config, trace);

		    String host = resolveHost(tlsVersion);
		    int    port = resolvePort(tlsVersion);
		    LOG.info("[{}] Connexion to {} : {}", tlsVersion, host, port);
		    LOG.info("[{}] Workflow execution : {} actions", tlsVersion, trace.getTlsActions().size());

		    WorkflowExecutor executor = WorkflowExecutorFactory
		            .createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
		    try {
		        executor.executeWorkflow();
		        LOG.info("[{}] Workflow terminated successfully", tlsVersion);
		    } catch (Exception e) {
		        LOG.error("[{}] Error occurred during the workflow execution", tlsVersion, e);
		    }

		    return state;
		}


		private Config resolveConfig(String tlsVersion) {
		    switch (tlsVersion) {
		        case "TLS_12": return clientConfig12.build();
		        case "TLS_13": return clientConfig13.build(); 
		        default:       return null;
		    }
		}

		private String resolveHost(String tlsVersion) {
		    switch (tlsVersion) {
		        case "TLS_12": return clientConfig12.getHost();
		        case "TLS_13": return clientConfig13.getHost();
		        default:       return "unknown";
		    }
		}

		private int resolvePort(String tlsVersion) {
		    switch (tlsVersion) {
		        case "TLS_12": return clientConfig12.getPort();
		        case "TLS_13": return clientConfig13.getPort();
		        default:       return -1;
		    }
		}
	 
	 
	 
}
