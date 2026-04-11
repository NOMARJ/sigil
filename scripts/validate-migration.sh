#!/usr/bin/env bash
# Validate lifecycle manifest migration coverage against legacy files.
# Compares pipeline.json, routing.json, and layers.json entries against
# lifecycle manifests in .nomark/lifecycles/manifests/.
set -euo pipefail

NOMARK_DIR=".nomark"
MANIFESTS_DIR="$NOMARK_DIR/lifecycles/manifests"
PIPELINE="$NOMARK_DIR/pipeline.json"
ROUTING="$NOMARK_DIR/routing.json"
LAYERS="$NOMARK_DIR/layers.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

total_mapped=0
total_unmapped=0
total_expected_unmapped=0

echo "=== Lifecycle Migration Validation ==="
echo ""

# --- pipeline.json ---
echo "--- pipeline.json ---"
if [ ! -f "$PIPELINE" ]; then
  echo "  SKIP: $PIPELINE not found"
else
  pipelines=$(node -e "const d=require('./$PIPELINE'); console.log(Object.keys(d.pipelines).join('\n'))")
  pipe_mapped=0
  pipe_unmapped=0
  for p in $pipelines; do
    manifest="$MANIFESTS_DIR/$p.yaml"
    if [ -f "$manifest" ]; then
      echo -e "  ${GREEN}MAPPED${NC}: pipeline '$p' → $manifest"
      pipe_mapped=$((pipe_mapped + 1))
      total_mapped=$((total_mapped + 1))
    else
      echo -e "  ${YELLOW}UNMAPPED${NC}: pipeline '$p' — no manifest at $manifest"
      pipe_unmapped=$((pipe_unmapped + 1))
      total_unmapped=$((total_unmapped + 1))
    fi
  done
  pipe_total=$((pipe_mapped + pipe_unmapped))
  echo "  Coverage: $pipe_mapped/$pipe_total pipelines mapped"
fi
echo ""

# --- routing.json ---
echo "--- routing.json ---"
if [ ! -f "$ROUTING" ]; then
  echo "  SKIP: $ROUTING not found"
else
  categories=$(node -e "const d=require('./$ROUTING'); console.log(Object.keys(d.categories).join('\n'))")
  route_noted=0
  for c in $categories; do
    echo -e "  ${YELLOW}DISPATCH-ONLY${NC}: category '$c' — stays in routing.json (classification, not lifecycle)"
    route_noted=$((route_noted + 1))
    total_expected_unmapped=$((total_expected_unmapped + 1))
  done
  echo "  Note: routing.json categories are dispatch concerns, not lifecycle stages."
  echo "  Expected unmapped: $route_noted (by design)"
fi
echo ""

# --- layers.json ---
echo "--- layers.json ---"
if [ ! -f "$LAYERS" ]; then
  echo "  SKIP: $LAYERS not found"
else
  compositions=$(node -e "const d=require('./$LAYERS'); console.log(Object.keys(d.compositions).join('\n'))")
  layer_mapped=0
  layer_unmapped=0
  for c in $compositions; do
    exec_skill=$(node -e "const d=require('./$LAYERS'); console.log(d.compositions['$c'].execution)")
    # Check if any manifest has a stage binding this skill
    found=false
    if [ -d "$MANIFESTS_DIR" ]; then
      for m in "$MANIFESTS_DIR"/*.yaml; do
        if [ -f "$m" ] && grep -q "- $exec_skill" "$m" 2>/dev/null; then
          found=true
          break
        fi
      done
    fi
    if $found; then
      echo -e "  ${GREEN}MAPPED${NC}: composition '$c' (execution: $exec_skill) → found in manifest skills"
      layer_mapped=$((layer_mapped + 1))
      total_mapped=$((total_mapped + 1))
    else
      echo -e "  ${YELLOW}UNMAPPED${NC}: composition '$c' (execution: $exec_skill) — skill not found in any manifest"
      layer_unmapped=$((layer_unmapped + 1))
      total_unmapped=$((total_unmapped + 1))
    fi
  done

  enhancements=$(node -e "const d=require('./$LAYERS'); console.log(Object.keys(d.layers.enhancements).join('\n'))")
  for e in $enhancements; do
    echo -e "  ${YELLOW}SKILL-INTERNAL${NC}: enhancement '$e' — inject strings stay in skill configs"
    total_expected_unmapped=$((total_expected_unmapped + 1))
  done
  layer_total=$((layer_mapped + layer_unmapped))
  echo "  Coverage: $layer_mapped/$layer_total compositions mapped"
fi
echo ""

# --- Summary ---
echo "=== Summary ==="
echo "  Mapped to manifests:    $total_mapped"
echo "  Unmapped (needs work):  $total_unmapped"
echo "  Expected unmapped:      $total_expected_unmapped (dispatch/skill-internal — by design)"
grand_total=$((total_mapped + total_unmapped))
if [ $grand_total -gt 0 ]; then
  pct=$((total_mapped * 100 / grand_total))
  echo "  Migration coverage:     ${pct}%"
else
  echo "  Migration coverage:     N/A (no entries)"
fi
echo ""
echo "Note: Full migration happens in F-028 (Code Lifecycle Extraction)."
echo "Legacy files are NOT deleted until behavioural equivalence is verified."
