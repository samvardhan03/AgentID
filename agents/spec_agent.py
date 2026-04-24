from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from .schema import GraphState, StructuredSpec

SPEC_AGENT_PROMPT = """You are the SpecForge SpecAgent, operating with strict, high-end academic precision.
Your primary objective is to translate the following natural language request into a rigorous, well-defined Pydantic specification constraint.
Analyze the user's intent, abstract the requirements into logical components, and ensure the resulting `StructuredSpec` is exhaustively detailed, deterministic, and modular.

User Request: {user_request}
"""

def spec_node(state: GraphState) -> dict:
    """
    Translates natural language into a StructuredSpec.
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    prompt = ChatPromptTemplate.from_messages([
        ("system", SPEC_AGENT_PROMPT),
        ("user", "Generate the structured specification.")
    ])
    
    chain = prompt | llm.with_structured_output(StructuredSpec)
    
    spec = chain.invoke({"user_request": state.user_request})
    
    return {"structured_spec": spec}
