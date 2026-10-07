"""Third-party consumers for the shared HTTP and encrypted-record fixtures."""
import asyncio
import os
import sys

base_url = os.environ["STOGAS_BASE_URL"]
key = os.environ["STOGAS_API_KEY"]
model = os.environ["STOGAS_MODEL"]
streaming = "--unary" not in sys.argv
prompt = "Say hello."


def run():
    library = sys.argv[1]
    if library == "langchain":
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(model=model, api_key=key, base_url=base_url, max_retries=0,
                         timeout=15, use_responses_api=False)
        if streaming:
            for chunk in llm.stream(prompt):
                print(chunk.content, end="", flush=True)
        else:
            print(llm.invoke(prompt).content)
    elif library == "llamaindex":
        from llama_index.core.llms import ChatMessage
        from llama_index.llms.openai_like import OpenAILike
        llm = OpenAILike(model=model, api_key=key, api_base=base_url, max_retries=0,
                         is_chat_model=True, timeout=15)
        messages = [ChatMessage(role="user", content=prompt)]
        if streaming:
            for chunk in llm.stream_chat(messages):
                print(chunk.delta or "", end="", flush=True)
        else:
            print(llm.chat(messages).message.content)
    elif library == "litellm":
        os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
        import litellm
        response = litellm.completion(model=f"openai/{model}", api_key=key, api_base=base_url,
            messages=[{"role": "user", "content": prompt}], stream=streaming,
            num_retries=0, timeout=15)
        if streaming:
            for chunk in response:
                for choice in chunk.choices:
                    print(choice.delta.content or "", end="", flush=True)
        else:
            print(response.choices[0].message.content)
    elif library == "pydantic-ai":
        asyncio.run(pydantic())
    else:
        raise ValueError(f"Unknown client {library}")


async def pydantic():
    from openai import AsyncOpenAI
    from pydantic_ai import Agent
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider
    async with AsyncOpenAI(api_key=key, base_url=base_url, max_retries=0, timeout=15) as client:
        agent = Agent(OpenAIChatModel(model, provider=OpenAIProvider(openai_client=client)), retries=0)
        if streaming:
            async with agent.run_stream(prompt) as response:
                async for text in response.stream_text(delta=True):
                    print(text, end="", flush=True)
        else:
            print((await agent.run(prompt)).output)


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        # Preserve the framework's typed HTTP status as an independent oracle.
        status = getattr(error, "status_code", getattr(error, "status", None))
        print(f"HTTP_STATUS={status}", file=sys.stderr)
        raise
