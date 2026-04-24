from .schema import GraphState

def docs_node(state: GraphState) -> dict:
    """
    Mock DocsAgent.
    Generates Obsidian-compatible markdown knowledge graph nodes upon successful execution.
    """
    docs = f"""## Component Architecture Knowledge Node

**Status**: Verified mathematically and structurally.
**Specification Link**: `[[{state.structured_spec.metadata.title if state.structured_spec else 'Unknown Component'}]]`
"""
    return {"documentation": docs}
