from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from .schema import GraphState

TEST_AGENT_PROMPT = """You are the SpecForge TestAgent, an automated verification theorist.
Your mission is to formulate an exhaustive `pytest` suite that structurally verifies the following Python implementation against its formal mathematical specification.
Cover all defined edge cases, normal inputs, and constraint boundary conditions.
Ensure tests are deterministic, isolated, and formatted with minimalist academic rigor.

Active Specification:
{spec}

Implementation to Verify:
{code}

Provide your academic reasoning trace, followed by the complete pytest suite code.
"""

class TestOutput(BaseModel):
    chain_of_thought: str = Field(description="Rigorous academic exposition of the test coverage strategy")
    tests: str = Field(description="The final pytest suite code block")

def test_node(state: GraphState) -> dict:
    """
    Generates a pytest suite covering happy paths and edge cases for the generated code.
    """
    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    prompt = ChatPromptTemplate.from_messages([
        ("system", TEST_AGENT_PROMPT),
        ("user", "Produce the rigorous test suite.")
    ])
    
    chain = prompt | llm.with_structured_output(TestOutput)
    
    spec_json = state.structured_spec.model_dump_json(indent=2) if state.structured_spec else ""
    code = state.generated_code or ""
    
    result = chain.invoke({
        "spec": spec_json,
        "code": code
    })
    
    return {"generated_tests": result.tests}
