from typing import Annotated

from langchain.agents import create_agent
from langchain_core.messages import HumanMessage

from AGENTS.agent_siem import tools
from Lib.api import get_current_time_str
from Lib.configs import DATA_DIR
from Lib.llmapi import load_system_prompt_template
from Lib.log import logger
from PLUGINS.LLM.llmapi import LLMAPI


# Alternative, simpler agent implementation using create_agent
def create_siem_agent(
        query: Annotated[str, "A natural language query for SIEM."]
) -> Annotated[str, "A summary of the findings from the SIEM search."]:
    """
a simpler, stateless agent created using the create_agent factory function from langchain.agents.
    """

    logger.info(f"Creating SIEM agent with query: {query[:100]}...")
    prompt_path = os.path.join(DATA_DIR, "Agent_SIEM", "system_prompt.md")
    logger.debug(f"Loading system prompt from: {prompt_path}")
    system_prompt = load_system_prompt_template(prompt_path).format(CURRENT_UTC_TIME=get_current_time_str())
    logger.debug(f"System prompt loaded successfully")

    llm_api = LLMAPI()
    llm = llm_api.get_model(tag=["fast", "function_calling"])
    logger.debug(f"LLM model obtained with tags: ['fast', 'function_calling']")

    logger.debug(f"Creating agent with {len(tools)} tools")
    agent = create_agent(llm, tools, system_prompt=system_prompt)
    logger.debug(f"Agent created successfully")

    logger.info(f"Invoking agent...")
    response = agent.invoke({"messages": [HumanMessage(content=query)]})
    logger.info(f"Agent invocation completed")

    result = response['messages'][-1].content
    logger.info(f"Agent result extracted, result length: {len(result)} characters")
    return result


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()

    print("\n--- Using create_agent for Query ---")
    test_query = "Have there been any suspicious logins for the user 'admin' on Windows machines?"
    result_simple = create_siem_agent(test_query)
    print(result_simple)
