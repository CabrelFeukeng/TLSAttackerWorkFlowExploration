package workflow;

import config.TlsClientConfig;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

public interface TlsWorkflowBuilder {
		
	public WorkflowTrace build(TlsClientConfig clientConfig);

}
