import importlib


def test_telemetry_disable_env(monkeypatch):
    monkeypatch.setenv("FIXOPS_DISABLE_TELEMETRY", "1")
    import telemetry  # noqa: F401

    module = importlib.reload(telemetry)
    module.configure()
    tracer = module.get_tracer("tests.telemetry")
    with tracer.start_as_current_span("noop"):
        pass
    meter = module.get_meter("tests.telemetry")
    counter = meter.create_counter("fixops.tests.telemetry")
    counter.add(1)


def test_telemetry_reconfigure_noop(monkeypatch):
    monkeypatch.delenv("FIXOPS_DISABLE_TELEMETRY", raising=False)
    import telemetry

    module = importlib.reload(telemetry)

    # First configure call should succeed even without OTEL packages (falls back to no-op)
    module.configure()
    # Second call should be a no-op and not raise
    module.configure()

    tracer = module.get_tracer()
    span_cm = tracer.start_as_current_span("second-call")
    assert hasattr(span_cm, "__enter__")
    with span_cm:
        pass

    meter = module.get_meter()
    counter = meter.create_counter("telemetry.reconfigure")
    counter.add(0)
