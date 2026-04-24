from langgraph.graph import StateGraph, END
from typing import Literal
from .schema import GraphState
from .spec_agent import spec_node
from .code_agent import code_node
from .test_agent import test_node
from .execution_agent import execution_node
from .debug_agent import debug_node
from .docs_agent import docs_node

def route_execution(state: GraphState) -> Literal["debug_node", "docs_node", "__end__"]:
    """
    Evaluates the execution results to determine the next phase of the LangGraph loop.
    Returns the name of the next node.
    """
    if state.test_result and not state.test_result.success:
        if state.revision_count >= state.max_revisions:
            # We reached max cycles without formal test compliance; abort loop.
            return "__end__"
        return "debug_node"
    
    return "docs_node"

def build_graph():
    """
    Constructs the core SpecForge LangGraph StateGraph (Track A).
    """
    workflow = StateGraph(GraphState)

    # 1. Define Nodes
    workflow.add_node("spec_node", spec_node)
    workflow.add_node("code_node", code_node)
    workflow.add_node("test_node", test_node)
    workflow.add_node("execution_node", execution_node)
    workflow.add_node("debug_node", debug_node)
    workflow.add_node("docs_node", docs_node)

    # 2. Define the Forward Execution Path
    workflow.set_entry_point("spec_node")
    workflow.add_edge("spec_node", "code_node")
    workflow.add_edge("code_node", "test_node")
    workflow.add_edge("test_node", "execution_node")
    
    # 3. Define the Conditional Routing
    # Here Track A delegates based on the deterministic outcome of the sandbox.
    workflow.add_conditional_edges(
        "execution_node",
        route_execution,
        {
            "debug_node": "debug_node",
            "docs_node": "docs_node",
            "__end__": END
        }
    )
    
    # 4. Define the Debugging Loop
    # The patch is evaluated by rewriting the tests or immediately re-executing.
    # In strict contexts, the patch should be run through the test_node or execution_node again.
    workflow.add_edge("debug_node", "test_node")
    
    # 5. Define Terminal Output
    workflow.add_edge("docs_node", END)

    return workflow.compile()

# Instantiated graph ready to be invoked or visualized
specforge_loop = build_graph()
