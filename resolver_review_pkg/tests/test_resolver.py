"""resolver_review 的 unittest 验收。

覆盖协议全部关键路径：
  * 多级别名链 + 链/授权最早截止 + 缓存命中与实际截止；
  * 否定项在另一分区越界（不能跨分区进口正项或否定项）；
  * 存活子树打破宽泛否定（仅扣除交叠子树，保留其余否定范围）；
  * 两链共享地址但一条撤销；
  * 同型别名形成闭环（报告最短闭环并结束）；
  * 故障期间限时旧正项兜底，以及现行否定/撤销始终禁止兜底；
  * compare 的候选等待短反例，以及小实例上对全部线性化做完整排列交叉验证。
"""

from __future__ import annotations

import itertools
import unittest

from resolver_review.cache import Cache, CacheEntry
from resolver_review.compare import run_compare
from resolver_review.model import RequestSpec, StaleConfig
from resolver_review.resolve import Engine
from resolver_review.simulate import run_simulate
from resolver_review.validator import parse_case
from resolver_review.view import View


def _view_with(partitions=("p",)) -> View:
    return View(tuple(partitions))


def _scope(view: View, partition="p", suffix="", generation="s1", expires=None) -> None:
    from resolver_review.model import Event, TrustScope

    scope = TrustScope(
        partition=partition, suffix=suffix, generation=generation,
        order=0, expires=expires, active=True,
    )
    view.apply_event(
        Event(id="t", index=0, slot=0, etype="trust_add", scope=scope)
    )


def _upsert(view, kind, name, generation, value=None, proof=None, partition="p",
            expires=None, order=0) -> None:
    from resolver_review.model import Event, Record

    rec = Record(
        kind=kind, partition=partition, name=name, generation=generation,
        order=order, expires=expires, value=value, proof=proof,
    )
    view.apply_event(Event(id=f"u{order}", index=order, slot=0, etype="upsert", record=rec))


def _admit(view, endpoint, admission_id="a1", partition="p", generation="ag1", expires=None) -> None:
    from resolver_review.model import Admission, Event

    adm = Admission(
        admission_id=admission_id, endpoint=endpoint, partition=partition,
        generation=generation, order=0, expires=expires, active=True,
    )
    view.apply_event(Event(id="ad", index=0, slot=0, etype="admission_add", admission=adm))


def _revoke(view, generation, partition="p") -> None:
    from resolver_review.model import Event

    view.apply_event(
        Event(id="r", index=0, slot=0, etype="revoke",
              rev_partition=partition, rev_generation=generation)
    )


def _req(name, service="svc", partition="p", stale=None) -> RequestSpec:
    return RequestSpec(
        name=name, service=service, partition=partition, order=0, stale=stale
    )


class LabelAlgebraTests(unittest.TestCase):
    def test_suffix_and_specificity(self):
        from resolver_review.model import is_suffix, specificity

        self.assertTrue(is_suffix("", "a.b.c"))
        self.assertTrue(is_suffix("b.c", "a.b.c"))
        self.assertTrue(is_suffix("a.b.c", "a.b.c"))
        self.assertFalse(is_suffix("x.c", "a.b.c"))
        self.assertFalse(is_suffix("b.c", "b.c.d"))
        self.assertEqual(specificity("a.b.c"), 3)
        self.assertEqual(specificity(""), 0)


class AliasChainTests(unittest.TestCase):
    def test_chain_deadline_uses_min_of_chain_and_admission(self):
        view = _view_with()
        _scope(view, suffix="")
        _admit(view, "ep1", expires=25)
        _upsert(view, "alias", "e", "g1", value="m", expires=40)
        _upsert(view, "alias", "m", "g2", value="h", expires=30)
        _upsert(view, "positive", "h", "g3", value="ep1")
        engine = Engine(view, Cache())

        result = engine.query(_req("e"), 1)
        self.assertEqual(result.decision, "resolved")
        self.assertEqual(result.chain, ["e", "m", "h"])
        # 链上最早截止 m=30，早于授权 25？取 min(40,30,25)=25。
        self.assertEqual(result.deadline, 25)

    def test_cache_hit_reports_cache_source_and_deadline(self):
        view = _view_with()
        _scope(view, suffix="")
        _admit(view, "ep1")
        _upsert(view, "positive", "h", "g1", value="ep1")
        cache = Cache()
        engine = Engine(view, cache)
        first = engine.query(_req("h"), 1)
        self.assertEqual(first.source, "live")
        second = engine.query(_req("h"), 2)
        self.assertEqual(second.source, "cache")
        self.assertEqual(second.endpoint, "ep1")
        self.assertEqual(second.deadline, first.deadline)


class PartitionIsolationTests(unittest.TestCase):
    def test_negative_in_other_partition_does_not_cross(self):
        view = _view_with(("pa", "pb"))
        _scope(view, partition="pa", suffix="", generation="sa")
        _scope(view, partition="pb", suffix="", generation="sb")
        _admit(view, "ep1", partition="pa")
        # pb 的根否定不得影响 pa。
        _upsert(view, "negative", "", "negpb", proof="P", partition="pb")
        _upsert(view, "positive", "x.pa", "g1", value="ep1", partition="pa")
        engine = Engine(view, Cache())

        result = engine.query(_req("x.pa", partition="pa"), 1)
        self.assertEqual(result.decision, "resolved")
        self.assertEqual(result.endpoint, "ep1")

    def test_positive_in_other_partition_not_imported(self):
        view = _view_with(("pa", "pb"))
        _scope(view, partition="pa", suffix="", generation="sa")
        _scope(view, partition="pb", suffix="", generation="sb")
        _upsert(view, "positive", "shared", "g1", value="ep1", partition="pb")
        engine = Engine(view, Cache())
        result = engine.query(_req("shared", partition="pa"), 1)
        self.assertEqual(result.decision, "no_record")


class NegativeSubtreeTests(unittest.TestCase):
    def test_wide_negative_denies_uncovered_name(self):
        view = _view_with()
        _scope(view, suffix="")
        _admit(view, "ep1")
        _upsert(view, "negative", "wide", "ng1", proof="P")
        engine = Engine(view, Cache())
        result = engine.query(_req("lonely.wide"), 1)
        self.assertEqual(result.decision, "negative_denied")
        self.assertEqual(result.negative_suffix, "wide")

    def test_existing_subtree_breaks_wide_negative_only_for_overlap(self):
        view = _view_with()
        _scope(view, suffix="")
        _admit(view, "ep1")
        _upsert(view, "negative", "wide", "ng1", proof="P", order=0)
        # 更具体的可信存在子树。
        _upsert(view, "positive", "kept.wide", "kg1", value="ep1", order=1)
        engine = Engine(view, Cache())

        kept = engine.query(_req("kept.wide"), 1)
        self.assertEqual(kept.decision, "resolved")
        lonely = engine.query(_req("lonely.wide"), 2)
        self.assertEqual(lonely.decision, "negative_denied")
        self.assertIn("kept.wide", lonely.subtracted)


class SharedAddressRevocationTests(unittest.TestCase):
    def test_two_chains_share_address_one_revoked(self):
        view = _view_with()
        _scope(view, suffix="")
        _admit(view, "ep_shared")
        # 两条链各自独立代次，终点指向同一获批地址。
        _upsert(view, "positive", "a", "ga", value="ep_shared")
        _upsert(view, "positive", "b", "gb", value="ep_shared")
        engine = Engine(view, Cache())
        self.assertEqual(engine.query(_req("a"), 1).decision, "resolved")
        self.assertEqual(engine.query(_req("b"), 1).decision, "resolved")

        _revoke(view, "ga")
        self.assertEqual(engine.query(_req("a"), 2).decision, "no_record")
        # 另一条链的代次未撤销，仍可解析到同一地址。
        still = engine.query(_req("b"), 2)
        self.assertEqual(still.decision, "resolved")
        self.assertEqual(still.endpoint, "ep_shared")

    def test_revocation_invalidates_bound_cache_generation(self):
        view = _view_with()
        _scope(view, suffix="")
        _admit(view, "ep1")
        _upsert(view, "positive", "a", "ga", value="ep1")
        cache = Cache()
        engine = Engine(view, cache)
        engine.query(_req("a"), 1)
        self.assertEqual(len(cache), 1)
        _revoke(view, "ga")
        removed = cache.invalidate_generation("p", "ga")
        self.assertEqual(removed, 1)
        self.assertEqual(len(cache), 0)


class AliasCycleTests(unittest.TestCase):
    def test_reports_shortest_cycle_and_stops(self):
        view = _view_with()
        _scope(view, suffix="")
        _upsert(view, "alias", "x", "gx", value="y")
        _upsert(view, "alias", "y", "gy", value="x")
        engine = Engine(view, Cache())
        result = engine.query(_req("x"), 1)
        self.assertEqual(result.decision, "alias_cycle")
        # 最短闭环 x -> y -> x。
        self.assertEqual(result.cycle, ["x", "y", "x"])
        self.assertEqual(result.cycle_length, 3)


class StaleFallbackTests(unittest.TestCase):
    def _stale_setup(self):
        view = _view_with()
        _scope(view, suffix="")
        _admit(view, "ep1")
        _upsert(view, "positive", "a", "ga", value="ep1", expires=5)
        cache = Cache()
        engine = Engine(view, cache)
        # 故障前建立正项缓存。
        warm = engine.query(_req("a", service="jobs"), 1)
        self.assertEqual(warm.decision, "resolved")
        return view, cache

    def test_stale_allowed_during_failure_within_grace(self):
        view, cache = self._stale_setup()
        view.failures["jobs"] = 6
        engine = Engine(view, cache)
        stale = StaleConfig(extra_slots=3, enabled=True)
        # slot 8：记录已过期（5），但 8 <= 5+3 且处于故障窗口。
        result = engine.query(_req("a", service="jobs", stale=stale), 8)
        self.assertEqual(result.source, "stale")
        self.assertEqual(result.decision, "resolved")
        self.assertEqual(result.deadline, 8)

    def test_stale_blocked_by_active_negative(self):
        view, cache = self._stale_setup()
        view.failures["jobs"] = 6
        _upsert(view, "negative", "a", "gneg", proof="P")
        engine = Engine(view, cache)
        stale = StaleConfig(extra_slots=10)
        result = engine.query(_req("a", service="jobs", stale=stale), 7)
        self.assertEqual(result.decision, "negative_denied")

    def test_stale_blocked_by_revocation(self):
        view, cache = self._stale_setup()
        view.failures["jobs"] = 6
        _revoke(view, "ga")
        engine = Engine(view, cache)
        stale = StaleConfig(extra_slots=10)
        result = engine.query(_req("a", service="jobs", stale=stale), 7)
        self.assertNotEqual(result.source, "stale")
        self.assertNotEqual(result.decision, "resolved")

    def test_stale_not_allowed_outside_failure_window(self):
        view, cache = self._stale_setup()
        engine = Engine(view, cache)
        stale = StaleConfig(extra_slots=10)
        result = engine.query(_req("a", service="jobs", stale=stale), 7)
        self.assertNotEqual(result.source, "stale")


class AdmissionTests(unittest.TestCase):
    def test_unadmitted_endpointall_rejected(self):
        view = _view_with()
        _scope(view, suffix="")
        _upsert(view, "positive", "a", "ga", value="ep_unapproved")
        engine = Engine(view, Cache())
        result = engine.query(_req("a"), 1)
        self.assertEqual(result.decision, "unadmitted")


class CompareTests(unittest.TestCase):
    def _load(self, name):
        import json
        import os

        path = os.path.join(os.path.dirname(__file__), "..", "examples", name)
        with open(path, "r", encoding="utf-8") as handle:
            return parse_case(json.load(handle), "compare")

    def test_equivalent_pair(self):
        result = run_compare(self._load("compare_eq_case.json"))
        self.assertTrue(result["equivalent"])
        self.assertFalse(result["truncated"])

    def test_diverging_pair_produces_witness(self):
        case = self._load("compare_diff_case.json")
        result = run_compare(case)
        self.assertFalse(result["equivalent"])
        witness = result["witness"]
        self.assertIn("authorization", [f["field"] for f in witness["differing_fields"]])
        # 区分序列必须是合法理想路径：每一步的依赖都在更早位置。
        index_of = {e.id: i for i, e in enumerate(case.events)}
        seen = set()
        for ev_id in witness["event_sequence"]:
            event = case.events[index_of[ev_id]]
            for dep in event.after:
                self.assertIn(dep, seen)
            seen.add(ev_id)
        # 候选等待短反例：分歧发生在撤销事件 revoke_v1 之前——
        # 两侧缓存绑定不同代次，撤销前授权依据已不同；若强行等到撤销之后，
        # 活目录反而会让两边收敛到同一记录，反例就消失了。
        self.assertNotIn("revoke_v1", witness["event_sequence"])
        self.assertEqual(witness["diverging_event"], "req_app")
        self.assertEqual(
            witness["observation_a"]["authorization"]["admission_id"], "ADM-V1"
        )
        self.assertEqual(
            witness["observation_b"]["authorization"]["admission_id"], "ADM-V2"
        )

    def test_state_cap_truncates_without_false_equivalence(self):
        import dataclasses

        case = self._load("compare_eq_case.json")
        # 极小预算：必然截断，此时绝不能报告 equivalent=true。
        limited = dataclasses.replace(case, max_states=5)
        result = run_compare(limited)
        self.assertTrue(result["truncated"])
        self.assertFalse(result["equivalent"])
        self.assertNotIn("witness", result)


class ExhaustiveLinearizationTests(unittest.TestCase):
    """小实例：枚举全部合法线性化，与 compare 的理想 BFS 结论交叉验证。"""

    def _small_case_doc(self):
        return {
            "mode": "compare",
            "partitions": ["p"],
            "names": ["a", "b"],
            "compare_fields": ["reachability", "name_list", "authorization"],
            "cache_a": {
                "entries": [
                    {"partition": "p", "name": "a", "kind": "positive",
                     "generation": "g1", "deadline": 99, "endpoint": "e1"}
                ]
            },
            "cache_b": {"entries": []},
            "events": [
                {"id": "trust", "slot": 0, "etype": "trust_add",
                 "scope": {"partition": "p", "suffix": "", "generation": "s1"}},
                {"id": "adm", "slot": 0, "etype": "admission_add",
                 "admission": {"admission_id": "A1", "endpoint": "e1",
                               "partition": "p", "generation": "ag1"}},
                {"id": "up", "slot": 1, "etype": "upsert", "after": ["trust", "adm"],
                 "record": {"kind": "positive", "partition": "p", "name": "a",
                            "generation": "g1", "value": "e1"}},
                {"id": "rev", "slot": 3, "etype": "revoke", "after": ["up"],
                 "partition": "p", "generation": "g1"},
                {"id": "req", "slot": 2, "etype": "request", "after": ["up"],
                 "request": {"name": "a", "service": "s", "partition": "p",
                             "lo": 1, "hi": 5}},
            ],
        }

    def test_bfs_matches_brute_force_linearizations(self):
        from resolver_review.compare import _answer, _build_view, _advance_cache

        case = parse_case(self._small_case_doc(), "compare")
        n = len(case.events)
        index_of = {e.id: i for i, e in enumerate(case.events)}
        after_masks = []
        for e in case.events:
            m = 0
            for dep in e.after:
                m |= 1 << index_of[dep]
            after_masks.append(m)

        bfs = run_compare(case)

        # 枚举全部排列，保留满足偏序的线性化。
        brute_equiv = True
        for perm in itertools.permutations(range(n)):
            mask = 0
            for i in perm:
                if after_masks[i] & ~mask:
                    break
                mask |= 1 << i
            else:
                view = _build_view(case, 0)
                ca = Cache.from_entries(case.cache_a or ())
                cb = Cache.from_entries(case.cache_b or ())
                for i in perm:
                    event = case.events[i]
                    view.apply_event(event)
                    _advance_cache(ca, view, case, i)
                    _advance_cache(cb, view, case, i)
                    if event.etype == "request":
                        req = event.request
                        oa = _answer(view, ca, req, event.slot)
                        ob = _answer(view, cb, req, event.slot)
                        for field in case.compare_fields:
                            if oa[field] != ob[field]:
                                brute_equiv = False
        self.assertEqual(bfs["equivalent"], brute_equiv)


class ValidationTests(unittest.TestCase):
    def test_structural_error_has_json_pointer(self):
        from resolver_review.errors import ValidationError

        bad = {
            "mode": "simulate",
            "partitions": ["p"],
            "events": [
                {"id": "e1", "slot": 0, "etype": "upsert",
                 "record": {"kind": "positive", "partition": "p",
                            "name": "a", "generation": "g1"}}
            ],
        }
        with self.assertRaises(ValidationError) as ctx:
            parse_case(bad, "simulate")
        self.assertEqual(ctx.exception.pointer, "/events/0/record/value")

    def test_bad_json_type_reports_pointer(self):
        from resolver_review.errors import ValidationError

        bad = {"mode": "simulate", "partitions": ["p"], "events": "not-array"}
        with self.assertRaises(ValidationError) as ctx:
            parse_case(bad, "simulate")
        self.assertEqual(ctx.exception.pointer, "/events")

    def test_root_level_pointer_has_no_double_slash(self):
        from resolver_review.errors import ValidationError

        bad = {
            "mode": "compare",
            "partitions": ["p"],
            "events": [
                {"id": "r", "slot": 1, "etype": "request",
                 "request": {"name": "a", "service": "s", "partition": "p",
                             "lo": 1, "hi": 2}}
            ],
        }
        with self.assertRaises(ValidationError) as ctx:
            parse_case(bad, "compare")
        self.assertEqual(ctx.exception.pointer, "/cache_a")

    def test_generation_reuse_rejected(self):
        from resolver_review.errors import ValidationError

        doc = {
            "mode": "simulate",
            "partitions": ["p"],
            "events": [
                {"id": "t", "slot": 0, "etype": "trust_add",
                 "scope": {"partition": "p", "suffix": "", "generation": "s1"}},
                {"id": "u1", "slot": 1, "etype": "upsert", "after": ["t"],
                 "record": {"kind": "positive", "partition": "p", "name": "a",
                            "generation": "same", "value": "e1"}},
                {"id": "u2", "slot": 2, "etype": "upsert", "after": ["u1"],
                 "record": {"kind": "positive", "partition": "p", "name": "b",
                            "generation": "same", "value": "e2"}},
                {"id": "r1", "slot": 3, "etype": "request", "after": ["u2"],
                 "request": {"name": "a", "service": "s", "partition": "p"}},
            ],
        }
        with self.assertRaises(ValidationError) as ctx:
            parse_case(doc, "simulate")
        self.assertIn("generation", ctx.exception.pointer)


class SimulateSampleTests(unittest.TestCase):
    def _load_simulate(self, name):
        import json
        import os

        path = os.path.join(os.path.dirname(__file__), "..", "examples", name)
        with open(path, "r", encoding="utf-8") as handle:
            return parse_case(json.load(handle), "simulate")

    def _requests_by_id(self, result):
        return {
            item["event_id"]: item["result"]
            for item in result["timeline"]
            if item["etype"] == "request"
        }

    def test_lifecycle_sample_covers_cache_revoke_stale(self):
        result = run_simulate(self._load_simulate("simulate_case.json"))
        reqs = self._requests_by_id(result)
        self.assertEqual(reqs["req_edge_live"]["source"], "live")
        self.assertEqual(reqs["req_edge_cache"]["source"], "cache")
        # 撤销事件使绑定代次的正项缓存失效。
        revokes = [it for it in result["timeline"] if it["etype"] == "revoke"]
        self.assertEqual(revokes[0]["cache_invalidated"], 1)
        # 撤销项即使带 stale 也禁止兜底。
        self.assertEqual(reqs["req_cdn_after_revoke"]["decision"], "no_record")
        self.assertNotEqual(reqs["req_cdn_after_revoke"]["source"], "stale")
        # 未撤销的旧正项在故障窗口内可限时兜底，截止含宽限。
        self.assertEqual(reqs["req_legacy_stale"]["source"], "stale")
        self.assertEqual(reqs["req_legacy_stale"]["effective_deadline"], 18)

    def test_policy_sample_covers_negative_subtree_unadmitted_cycle(self):
        result = run_simulate(self._load_simulate("simulate_policy_case.json"))
        reqs = self._requests_by_id(result)
        # 另一分区的根否定不得跨分区影响 zone_pa。
        self.assertEqual(reqs["req_cross_partition"]["decision"], "resolved")
        # 宽泛否定对未被存在子树覆盖的名称仍然生效。
        lonely = reqs["req_lonely_denied"]
        self.assertEqual(lonely["decision"], "negative_denied")
        self.assertIn("kept.wide.pa", lonely["subtracted_subtrees"])
        # 更具体的可信存在子树打破宽泛否定。
        self.assertEqual(reqs["req_kept_alive"]["decision"], "resolved")
        # 未获批 endpoint 被拒绝。
        self.assertEqual(reqs["req_unadmitted"]["decision"], "unadmitted")
        # 同型别名闭环，报告最短闭环。
        self.assertEqual(reqs["req_cycle"]["decision"], "alias_cycle")
        self.assertEqual(reqs["req_cycle"]["cycle"], ["loop.x", "loop.y", "loop.x"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
