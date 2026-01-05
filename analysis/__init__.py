
import importlib
import sys

module_name = "semantic_graphs"

try:
    mod = importlib.import_module(f"analysis.{module_name}")
except ModuleNotFoundError:
    print(f"[FATAL] Modül bulunamadı: analysis.{module_name}.py", file=sys.stderr)
    sys.exit(1)

build_fn = getattr(mod, "build_api_graph_compact", None)
analyze_fn = getattr(mod, "analyze_malware_semantically", None)

if build_fn is None or analyze_fn is None:
    print(f"[FATAL] {module_name} içinde build_api_graph_compact ve analyze_malware_semantically olmalı.", file=sys.stderr)
    sys.exit(1)