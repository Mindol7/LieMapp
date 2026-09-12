"""Explicit LLVM CPU output-channel scheduling variant for AMA feasibility.

This is NOT upstream MLC behavior or merely logging instrumentation. It changes
only the execution schedule of selected generated TIR matmul kernels. Parameter
bytes, model graph, quantization, reduction-k order, parser and sampling remain
unchanged. Independent numerical verification is required before any evaluation.
"""
from __future__ import annotations

import json
from pathlib import Path

import tvm
from tvm import s_tir, tirx
from tvm.s_tir.dlight.analysis import normalize_prim_func
from tvm.s_tir.dlight.base import try_inline_contiguous_spatial

VARIANT = "llvm-cpu-output-channel-v1"
LANES = 8


def apply_schedule(func, name="main"):
    """Return (scheduled function or None, auditable decision record)."""
    record = {"name": name, "variant": VARIANT, "applied": False,
              "reduction_order_changed": False, "vectorized_reduction": False}
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
        if not kinds.endswith("SR") or kinds.count("R") != 1 or any(k != "S" for k in kinds[:-1]):
            record["reason"] = "requires_spatial_axes_followed_by_one_reduction"
            return None, record
        loops = sch.get_loops(info.block_rv)
        if len(loops) != len(info.iters) or len(loops) < 2:
            record["reason"] = "requires_one_or_more_spatial_axes"
            return None, record
        outer_spatial, channel, reduction = list(loops[:-2]), loops[-2], loops[-1]
        channel_outer, channel_inner = sch.split(channel, factors=[None, LANES])
        sch.reorder(*outer_spatial, channel_outer, reduction, channel_inner)
        # Only independent output channels are vector lanes. The original k
        # traversal stays sequential and in the original direction/order.
        sch.vectorize(channel_inner)
        task = sch.fuse(*outer_spatial, channel_outer)
        sch.parallel(task)
        # Parallel/vector scheduling requires the reduction's init to remain
        # attached while TVM checks compact dataflow; decompose it last.
        sch.decompose_reduction(info.block_rv, reduction)
        # Epilogues retain their original computation/order. They are small
        # compared with matmul and are intentionally not fused into this pass.
        record.update({"applied": True, "reason": "independent_output_tiles_parallel_and_channels_vectorized",
                       "reduction_block": info.name, "domain_kinds": kinds,
                       "lanes": LANES, "schedule_trace": str(sch.trace)})
        return sch.mod["main"].with_attr("tirx.is_scheduled", True), record
    except Exception as exc:
        record["reason"] = "schedule_rejected_by_TVM"
        record["exception_type"] = type(exc).__name__
        record["exception"] = str(exc)
        return None, record


def make_pass(output_dir):
    """Capture full stock/candidate IR and every applied/skipped kernel decision."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "kernels").mkdir()

    @tvm.transform.module_pass(opt_level=0, name="LieMappExplicitCPUOutputChannelSchedule")
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
        report = {"variant": VARIANT, "lanes": LANES, "applied": sum(r["applied"] for r in decisions),
                  "decisions": decisions, "validation_required": True,
                  "no_evaluation_fixture_used": True, "reduction_order_preserved_by_design": True}
        (output_dir / "schedule-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n")
        print(json.dumps({"schedule_variant": VARIANT, "applied_kernels": report["applied"],
                          "total_functions": len(decisions)}), flush=True)
        if not report["applied"]:
            raise RuntimeError("No CPU matmul kernel was scheduled; refusing to call this an optimized build")
        return mod

    return transform
