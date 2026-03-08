"""Tests for Fuzzy Identity Resolver — abbreviation expansion and asset matching."""

from core.services.fuzzy_identity import ABBREVIATIONS


class TestAbbreviations:
    def test_prod_to_production(self):
        assert ABBREVIATIONS["prod"] == "production"

    def test_stg_to_staging(self):
        assert ABBREVIATIONS["stg"] == "staging"

    def test_dev_to_development(self):
        assert ABBREVIATIONS["dev"] == "development"

    def test_svc_to_service(self):
        assert ABBREVIATIONS["svc"] == "service"

    def test_k8s_to_kubernetes(self):
        assert ABBREVIATIONS["k8s"] == "kubernetes"

    def test_db_to_database(self):
        assert ABBREVIATIONS["db"] == "database"

    def test_lb_to_loadbalancer(self):
        assert ABBREVIATIONS["lb"] == "loadbalancer"

    def test_auth_to_authentication(self):
        assert ABBREVIATIONS["auth"] == "authentication"

    def test_sec_to_security(self):
        assert ABBREVIATIONS["sec"] == "security"

    def test_vuln_to_vulnerability(self):
        assert ABBREVIATIONS["vuln"] == "vulnerability"

    def test_all_values_are_strings(self):
        for k, v in ABBREVIATIONS.items():
            assert isinstance(k, str), f"Key {k} is not a string"
            assert isinstance(v, str), f"Value {v} is not a string"
            assert len(k) > 0
            assert len(v) > 0

    def test_cloud_provider_abbreviations(self):
        """Cloud provider short names should map correctly."""
        assert ABBREVIATIONS["eks"] == "kubernetes"
        assert ABBREVIATIONS["aks"] == "kubernetes"
        assert ABBREVIATIONS["gke"] == "kubernetes"
        assert ABBREVIATIONS["ec2"] == "compute"

    def test_network_abbreviations(self):
        assert ABBREVIATIONS["elb"] == "loadbalancer"
        assert ABBREVIATIONS["alb"] == "loadbalancer"
        assert ABBREVIATIONS["nlb"] == "loadbalancer"

    def test_messaging_abbreviations(self):
        assert ABBREVIATIONS["mq"] == "messagequeue"
        assert ABBREVIATIONS["sqs"] == "messagequeue"

    def test_environment_abbreviations(self):
        assert ABBREVIATIONS["env"] == "environment"
        assert ABBREVIATIONS["ns"] == "namespace"
        assert ABBREVIATIONS["cls"] == "cluster"

    def test_common_infra_abbreviations(self):
        assert ABBREVIATIONS["fe"] == "frontend"
        assert ABBREVIATIONS["be"] == "backend"
        assert ABBREVIATIONS["gw"] == "gateway"
        assert ABBREVIATIONS["cfg"] == "config"
        assert ABBREVIATIONS["mgmt"] == "management"
