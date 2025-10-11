from core.processing_layer import ProcessingLayer


def test_processing_layer_generates_composite_analysis() -> None:
    layer = ProcessingLayer()
    result = layer.evaluate(
        sbom_components=[{"name": "customer-api", "version": "1.4.2", "severity": "high"}],
        sarif_findings=[
            {
                "rule_id": "SNYK-JS-1",
                "level": "warning",
                "raw": {
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "customer-api"}
                            }
                        }
                    ]
                },
            }
        ],
        cve_records=[{"cve_id": "CVE-2024-1234", "severity": "critical", "components": ["customer-api"]}],
        context={
            "exposure": "open",
            "mission_impact": "mev",
            "utility": "efficient",
            "safety_impact": "marginal",
            "exploitation": "poc",
        },
        cnapp_exposures=[{"asset": "customer-api", "traits": ["internet_exposed"]}],
    )

    payload = result.to_dict()
    assert payload["knowledge_graph"]["metrics"]["nodes"] >= 1
    assert payload["non_cve_findings"], "Expected non-CVE findings summary"
    assert payload["markov_projection"]["forecast"], "Projection should include forecast data"
    assert "risk" in payload["bayesian_priors"]
    assert payload["library_status"]["networkx"] is True
