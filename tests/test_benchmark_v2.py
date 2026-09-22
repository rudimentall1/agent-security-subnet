import unittest

from subnet.benchmark_v2 import run_benchmark, summarize


class TestBenchmarkV2(unittest.TestCase):
    SEED = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff"
    )

    def test_full_matrix_shape(self):
        material, rows = run_benchmark(self.SEED)
        summary = summarize(material, rows)

        self.assertEqual(summary["scenario_families"], 20)
        self.assertEqual(summary["hidden_seeds"], 50)
        self.assertEqual(summary["unique_instances"], 1000)
        self.assertEqual(summary["miners"], 10)
        self.assertEqual(summary["evaluations"], 10000)
        self.assertEqual(summary["invalid_claims"], 0)

    def test_metrics_are_bounded(self):
        material, rows = run_benchmark(self.SEED)
        summary = summarize(material, rows)

        for key in (
            "instance_discovery_rate",
            "evaluation_discovery_rate",
            "false_positive_rate",
            "severity_weighted_recall",
        ):
            self.assertGreaterEqual(summary[key], 0.0)
            self.assertLessEqual(summary[key], 1.0)

        self.assertGreater(summary["unique_instances_discovered"], 0)
        self.assertGreater(summary["verified_findings"], 0)
        self.assertGreater(summary["cost_per_verified_finding"], 0)

    def test_seed_commitment_is_deterministic(self):
        material, rows = run_benchmark(self.SEED)
        summary = summarize(material, rows)

        self.assertEqual(
            summary["seed_commitment"],
            "4773d12e2371bb935b9a0f5439b4a1c3ad3f2414b86980f8418d1cfabdfadfef",
        )


if __name__ == "__main__":
    unittest.main()
