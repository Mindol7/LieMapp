"""Independent M4 x N8 LLVM scheduling candidate; no model/math change.

The reduction axis is never split, reordered, vectorized, or reassociated.
Four independent input rows share a reduction iteration and output-channel
vector. Their unrolled expressions expose identical weight dequantization to
LLVM common-subexpression elimination. This is an optimization opportunity,
not an assumed speedup: actual kernels and native inference must be verified.
"""
from __future__ import annotations

import json
from pathlib import Path

import tvm
from tvm import s_tir, tirx
from tvm.s_tir.dlight.analysis import normalize_prim_func
from tvm.s_tir.dlight.base import try_inline_contiguous_spatial

from cpu_schedule import apply_schedule as channel_schedule

VARIANT = "llvm-cpu-row4-channel8-v2"
ROWS = 4
LANES = 8


def apply_schedule(func, name="main"):
    record = {"name": name, "variant": VARIANT, "applied": False,
              "reduction_order_changed": False, "vectorized_reduction": False,
              "row_tile": ROWS, "channel_tile": LANES}
    if not isinstance(func, tirx.PrimFunc):
        record["reason"] = "not_a_TIR_PrimFunc"
        return None, record
    if func.attrs.get("tirx.is_scheduled", False):
        record["reason"] = "upstream_already_scheduled"
        return None, record
    if "matmul" not in name.lower():
        record["reason"] = "outside_explicit_matmul_family"
        return None, record
    target = func.attrs.get("target")
    if target is not None and target.kind.name != "llvm":
        record["reason"] = "not_LLVM"
        return None, record
    try:
        sch = s_tir.Schedule(func)
        infos = normalize_prim_func(sch)
        if infos is None:
            record["reason"] = "normalization_not_supported"
            return None, record
        record["blocks_before_inline"] = [str(block) for block in infos]
        infos = try_inline_contiguous_spatial(sch, infos)
        if infos is None:
            record["reason"] = "producer_inline_not_supported"
            return None, record
        record["blocks_after_inline"] = [str(block) for block in infos]
        reductions = [block for block in infos if block.is_reduction()]
        if len(reductions) != 1:
            record["reason"] = "requires_exactly_one_reduction_block"
            return None, record
        info = reductions[0]
        kinds = info.dom_kind()
        # Normalization removes compile-time unit spatial dimensions. A
        # single-row GEMV has no row loop and uses the preserved v1 schedule.
        if kinds == "SR":
            result, previous = channel_schedule(func, name)
            record.update({"applied": previous["applied"],
                           "reason": "single_row_uses_unchanged_v1_channel_schedule",
                           "domain_kinds": kinds, "inherited_v1_decision": previous})
            return result, record
        if kinds != "SSR":
            record["reason"] = "requires_row_channel_reduction_domain"
            return None, record
        loops = sch.get_loops(info.block_rv)
        if len(loops) != 3:
            record["reason"] = "requires_three_normalized_loops"
            return None, record
        row, channel, reduction = loops
        row_outer, row_inner = sch.split(row, factors=[None, ROWS])
        channel_outer, channel_inner = sch.split(channel, factors=[None, LANES])
        sch.reorder(row_outer, channel_outer, reduction, row_inner, channel_inner)
        sch.unroll(row_inner)
        sch.vectorize(channel_inner)
        task = sch.fuse(row_outer, channel_outer)
        sch.parallel(task)
        sch.decompose_reduction(info.block_rv, reduction)
        record.update({"applied": True, "reason": "independent_4row_8channel_tiles_with_original_k_order",
                       "reduction_block": info.name, "domain_kinds": kinds,
                       "tail_strategy": "TVM split predicates retain exact original row/channel domain",
                       "weight_reuse": "same-k dequant expressions exposed for LLVM CSE across unrolled rows",
                       "schedule_trace": str(sch.trace)})
        return sch.mod["main"].with_attr("tirx.is_scheduled", True), record
    except Exception as error:
        record.update({"reason": "schedule_rejected_by_TVM",
                       "exception_type": type(error).__name__, "exception": str(error)})
        return None, record


def make_pass(output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "kernels").mkdir()

    @tvm.transform.module_pass(opt_level=0, name="LieMappExplicitCPUFourRowChannelSchedule")
    def transform(mod, _context):
        (output_dir / "before_schedule.json").write_text(tvm.ir.save_json(mod))
        (output_dir / "before_schedule.py").write_text(mod.script(show_meta=True))
        decisions = []
        for global_var, func in list(mod.functions_items()):
            name = global_var.name_hint
            scheduled, decision = apply_schedule(func, name)
            decisions.append(decision)
            if scheduled is not None:
                (output_dir / "kernels" / f"{name}.before.py").write_text(func.script(show_meta=True))
                (output_dir / "kernels" / f"{name}.after.py").write_text(scheduled.script(show_meta=True))
                mod[global_var] = scheduled
        (output_dir / "after_schedule.json").write_text(tvm.ir.save_json(mod))
        (output_dir / "after_schedule.py").write_text(mod.script(show_meta=True))
        row_tiled = sum(row["applied"] and row.get("domain_kinds") == "SSR" for row in decisions)
        report = {"variant": VARIANT, "lanes": LANES, "row_tile": ROWS,
                  "applied": sum(row["applied"] for row in decisions),
                  "row_tiled": row_tiled, "decisions": decisions,
                  "validation_required": True, "no_evaluation_fixture_used": True,
                  "reduction_order_preserved_by_design": True}
        (output_dir / "schedule-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n")
        print(json.dumps({"schedule_variant": VARIANT, "applied_kernels": report["applied"],
                          "row_tiled_kernels": row_tiled, "total_functions": len(decisions)}), flush=True)
        if not row_tiled:
            raise RuntimeError("No M4xN8 kernel was scheduled; rejecting ineffective candidate")
        return mod

    return transform
