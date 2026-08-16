"""Reasoner parsing and fallback behaviour. `python tests/test_reasoner.py`

No network: the provider call is monkeypatched. What's under test is the part that
actually bites — parsing an untrusted model response, and what happens when the
provider fails.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from aegis import reasoner                                               # noqa: E402

ATTACK = ("Our bank account has changed, remit to IBAN GB29 NWBK 60161331926819 "
          "urgently and keep it confidential.")
# Deliberately free of every keyword in aegis/signals.py — this is the class of message
# the model exists to catch. test_model_adds_a_paraphrase_the_keywords_miss asserts that
# the offline detector really does miss it, so the test fails loudly if that stops
# being true rather than quietly testing nothing.
PARAPHRASE = "Going forward, funds should be directed elsewhere - I'll share where separately."


class _patch:
    """Temporarily set env vars and a provider function."""

    def __init__(self, call=None, **env):
        self.env, self.call = env, call
        self.saved, self.saved_call = {}, None

    def __enter__(self):
        for k, v in self.env.items():
            self.saved[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.saved_call = reasoner._call_anthropic
        if self.call:
            reasoner._call_anthropic = self.call
        return self

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        reasoner._call_anthropic = self.saved_call


def test_offline_when_no_provider_configured():
    with _patch(ANTHROPIC_API_KEY=None, LLM_API_KEY=None):
        types = {s["type"] for s in reasoner.classify({"text": ATTACK})}
    assert {"payment_change", "urgency", "secrecy", "iban_present"} <= types


def test_every_signal_carries_a_confidence():
    with _patch(ANTHROPIC_API_KEY=None, LLM_API_KEY=None):
        sigs = reasoner.classify({"text": ATTACK})
    assert all("confidence" in s for s in sigs)
    assert all(0.0 <= s["confidence"] <= 1.0 for s in sigs)


def test_provider_failure_falls_back_instead_of_going_blind():
    def boom(_text):
        raise RuntimeError("503 from provider")

    with _patch(call=boom, ANTHROPIC_API_KEY="test-key"):
        types = {s["type"] for s in reasoner.classify({"text": ATTACK})}
    assert "payment_change" in types, "a provider outage must not disable detection"


def test_model_output_is_merged_with_the_regex_iban():
    def fake(_text):
        return reasoner._coerce('[{"type":"payment_change","evidence":"updated account",'
                                '"confidence":0.9}]')

    with _patch(call=fake, ANTHROPIC_API_KEY="test-key"):
        sigs = reasoner.classify({"text": ATTACK})
    by_type = {s["type"]: s for s in sigs}
    assert by_type["iban_present"]["evidence"] == "GB29NWBK60161331926819"
    assert by_type["iban_present"]["confidence"] == 1.0


def test_an_empty_model_response_cannot_disarm_the_detector():
    """The failure this guards: a refusal, a truncated response, or a prompt injection
    in the vendor's message convincing the model to return nothing."""
    with _patch(call=lambda _t: [], ANTHROPIC_API_KEY="test-key"):
        sigs = reasoner.classify({"text": ATTACK})
    types = {s["type"] for s in sigs}
    assert {"payment_change", "urgency", "secrecy", "iban_present"} <= types, (
        "the offline detector must be a floor, not an alternative")


def test_the_model_cannot_talk_a_deterministic_signal_down():
    def timid(_text):
        return reasoner._coerce('[{"type":"payment_change","evidence":"eh","confidence":0.05}]')

    with _patch(call=timid, ANTHROPIC_API_KEY="test-key"):
        sigs = reasoner.classify({"text": ATTACK})
    conf = next(s["confidence"] for s in sigs if s["type"] == "payment_change")
    assert conf == 1.0, "keyword evidence sets a floor the model cannot lower"


def test_model_adds_a_paraphrase_the_keywords_miss():
    from aegis import signals as offline
    assert not any(s["type"] == "payment_change" for s in offline.detect(PARAPHRASE)), (
        "fixture is stale: the keyword detector now catches this on its own")

    def fake(_text):
        return reasoner._coerce('[{"type":"payment_change","evidence":"updated account",'
                                '"confidence":0.85}]')

    with _patch(call=fake, ANTHROPIC_API_KEY="test-key"):
        sigs = reasoner.classify({"text": PARAPHRASE})
    by_type = {s["type"]: s for s in sigs}
    assert by_type["payment_change"]["confidence"] == 0.85, (
        "a model-only signal keeps the model's confidence")


def test_fenced_json_is_parsed():
    out = reasoner._coerce('```json\n[{"type":"urgency","evidence":"now"}]\n```')
    assert out == [{"type": "urgency", "evidence": "now", "confidence": 1.0}]


def test_unknown_types_and_junk_are_dropped():
    out = reasoner._coerce('[{"type":"mind_control","evidence":"x"},'
                           '"not an object",'
                           '{"type":"iban_present","evidence":"GB00"},'
                           '{"type":"secrecy","evidence":"quiet","confidence":"nonsense"}]')
    assert [s["type"] for s in out] == ["secrecy"], (
        "unknown types, non-objects and model-reported IBANs must all be dropped")
    assert out[0]["confidence"] == 1.0


def test_confidence_is_clamped():
    out = reasoner._coerce('[{"type":"urgency","evidence":"x","confidence":7}]')
    assert out[0]["confidence"] == 1.0


def test_signals_wrapper_object_is_accepted():
    out = reasoner._coerce('{"signals":[{"type":"urgency","evidence":"asap"}]}')
    assert len(out) == 1


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failed += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:                             # noqa: BLE001
                failed += 1
                print(f"ERROR {name}: {type(e).__name__}: {e}")
    sys.exit(1 if failed else 0)
