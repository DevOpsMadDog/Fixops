import httpx
import asyncio


async def test():
    canary = "aldeci-evil.example.com"
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as c:
        baseline = await c.get("https://www.yahoo.com", timeout=10.0)
        has_canary_baseline = canary in baseline.text
        print(f"Baseline status: {baseline.status_code}")
        print(f"Baseline has canary: {has_canary_baseline}")
        print(f"Baseline body length: {len(baseline.text)}")

        evil_resp = await c.get(
            "https://www.yahoo.com",
            headers={"Host": canary},
            timeout=10.0,
        )
        has_canary_evil = canary in evil_resp.text
        print(f"Evil status: {evil_resp.status_code}")
        print(f"Evil has canary: {has_canary_evil}")
        print(f"Evil body length: {len(evil_resp.text)}")

        if has_canary_evil and not has_canary_baseline:
            idx = evil_resp.text.find(canary)
            start = max(0, idx - 80)
            end = min(len(evil_resp.text), idx + len(canary) + 80)
            context = evil_resp.text[start:end]
            print(f"Canary context: ...{context}...")
            print("VERDICT: Host header IS reflected - REAL finding")
        elif has_canary_evil:
            print("VERDICT: Canary in both responses - false positive")
        else:
            print("VERDICT: Canary NOT reflected - false positive in scanner")


asyncio.run(test())

