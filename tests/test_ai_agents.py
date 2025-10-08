from core.ai_agents import AIAgentAdvisor


def test_ai_agent_advisor_detects_frameworks() -> None:
    advisor = AIAgentAdvisor(
        {
            "framework_signatures": [
                {"name": "LangChain", "keywords": ["langchain"]},
                {"name": "AutoGPT", "keywords": ["autogpt"]},
            ],
            "controls": {
                "default": {"recommended_controls": ["audit"]},
                "autogpt": {"recommended_controls": ["manual"]},
            },
            "playbooks": [
                {"name": "AI Hardening", "triggers": ["agent"], "frameworks": ["LangChain"]}
            ],
        }
    )

    design_rows = [
        {"component": "agent-service", "notes": "Runs LangChain orchestrator"},
        {"component": "ops-cli", "notes": ""},
    ]
    crosswalk = [
        {
            "design_row": design_rows[0],
            "sbom_component": {"description": "LangChain runtime"},
            "findings": [],
            "cves": [],
        },
        {"design_row": design_rows[1], "findings": [], "cves": []},
    ]

    analysis = advisor.analyse(design_rows, crosswalk)
    assert analysis is not None
    assert analysis["summary"]["components_with_agents"] == 1
    match = analysis["matches"][0]
    assert match["framework"] == "LangChain"
    assert match["recommended_controls"] == ["audit"]
