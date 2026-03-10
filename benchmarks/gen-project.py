#!/usr/bin/env python3
"""Generate a Pulumi YAML project with N random:RandomString resources.

Each resource produces ~1-2 KB of state (URN, inputs, outputs, provider ref).
To simulate larger real-world state (~16 KB/resource), resources include
a keepers map with padding data that persists in state.

Usage: python3 gen-project.py <output-dir> <resource-count> [--pad-kb=16]
"""

import os
import sys
import textwrap

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <output-dir> <resource-count> [--pad-kb=16]")
        sys.exit(1)

    out_dir = sys.argv[1]
    count = int(sys.argv[2])
    pad_kb = 16
    for arg in sys.argv[3:]:
        if arg.startswith("--pad-kb="):
            pad_kb = int(arg.split("=")[1])

    os.makedirs(out_dir, exist_ok=True)

    # Padding per resource to reach target state size
    pad_chars = max(0, pad_kb * 1024 - 500)  # ~500 bytes overhead per resource
    pad = "x" * pad_chars

    lines = [
        "name: bench-project",
        "runtime: yaml",
        "",
        "resources:",
    ]

    for i in range(1, count + 1):
        lines.append(f"  res-{i:04d}:")
        lines.append("    type: random:index/randomString:RandomString")
        lines.append("    properties:")
        lines.append("      length: 32")
        lines.append("      special: false")
        lines.append("      keepers:")
        lines.append(f"        index: \"{i}\"")
        if pad_chars > 0:
            lines.append(f"        pad: \"{pad}\"")
        lines.append("")

    lines.append("outputs:")
    lines.append(f"  totalResources: {count}")

    with open(os.path.join(out_dir, "Pulumi.yaml"), "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {count} resources in {out_dir}/Pulumi.yaml ({pad_kb} KB/resource target)")


if __name__ == "__main__":
    main()
