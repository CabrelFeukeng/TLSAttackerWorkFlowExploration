package executer;


import config.TlsClientConfig;
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

	 private final TlsClientConfig clientConfig = TlsClientConfig.getInstance();
	 
	 private static TlsWorkflowExecutor instance;
	 
	 private TlsWorkflowExecutor() {} 
	    
	 public static TlsWorkflowExecutor getInstance() {
	        if (instance == null) {
	            instance = new TlsWorkflowExecutor();
	        }
	        return instance;
	    }
	 
	 public State execute(WorkflowTrace trace) {
		 Config config = clientConfig.buid();
		 
		 State state = new State(config, trace);
		 
		
		 
		 LOG.info("Connexion to {} : {}", clientConfig.getHost(), clientConfig.getPort());
		 LOG.info("Workflow execution : {} actions", trace.getTlsActions().size());
		 
		 WorkflowExecutor executor = WorkflowExecutorFactory
				                     .createWorkflowExecutor(
				                    		 WorkflowExecutorType.DEFAULT,
				                    		 state
                                     );
		 try {
			 executor.executeWorkflow();
			 LOG.info("Workflow terminated successfully");
		 }catch(Exception e) {
			 LOG.error("error occured during the workflow execution", e);
		 }
		 
         return state;
	 }
	 
	 
	 
	 
}
