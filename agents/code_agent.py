from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from .schema import GraphState

CODE_AGENT_PROMPT = """You are the SpecForge CodeAgent, an elite logic synthesis entity.
Your objective is to generate production-ready Python code derived strictly from the active mathematical/logical specification.
Adopt a minimalist, high-end academic reasoning trace (chain-of-thought).
Ensure all type hints, docstrings, and constraints defined in the spec are flawlessly implemented.

Active Specification:
{spec}

Provide your response wrapped in a rigorous chain-of-thought reasoning, followed by the final implementation.
"""

class CodeOutput(BaseModel):
    chain_of_thought: str = Field(description="High-end academic reasoning trace outlining your architectural approach")
    code: str = Field(description="The finalized Python code execution block")

def code_node(state: GraphState) -> dict:
    """
    Generates Python code code using a chain-of-thought trace based on the structured specification.
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    prompt = ChatPromptTemplate.from_messages([
        ("system", CODE_AGENT_PROMPT),
        ("user", "Synthesize the implementation.")
    ])
    
    chain = prompt | llm.with_structured_output(CodeOutput)
    
    spec_json = state.structured_spec.model_dump_json(indent=2) if state.structured_spec else ""
    
    result = chain.invoke({"spec": spec_json})
    
    return {"generated_code": result.code}
