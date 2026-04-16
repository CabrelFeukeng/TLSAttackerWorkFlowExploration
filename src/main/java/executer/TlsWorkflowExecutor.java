package executer;


import config.TlsClientConfig;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TlsWorkflowExecutor {

	 private static final Logger LOG = LoggerFactory.getLogger(TlsWorkflowExecutor.class);
     
	 private TlsClientConfig clientConfig;
	 private WorkflowTrace trace;
	 
	 public TlsWorkflowExecutor(TlsClientConfig clientConfig, WorkflowTrace trace) {
		 this.clientConfig = clientConfig;
		 this.trace = trace;
	 } 
	 
	 
	 public State execute() {
  
		    State state = new State(clientConfig.build(), trace);
		    
		    LOG.info("[{}] Connexion to {} : {}", clientConfig.getTlsVersion(), clientConfig.getHost(), clientConfig.getPort());
		    LOG.info("[{}] Workflow execution : {} actions", clientConfig.getTlsVersion(), trace.getTlsActions().size());

		    WorkflowExecutor executor = WorkflowExecutorFactory
		            .createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
		    try {
		        executor.executeWorkflow();
		        LOG.info("[{}] Workflow terminated successfully", clientConfig.getTlsVersion());
		    } catch (Exception e) {
		        LOG.error("[{}] Error occurred during the workflow execution", clientConfig.getTlsVersion(), e);
		    }

		    return state;
		}
	 
}
