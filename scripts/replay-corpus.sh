#!/usr/bin/env bash
# replay-corpus.sh — test-corpus/ 의 regression case 재실행.
#
# axiom_id 기준 디렉터리 구조. 선제 검증 / PR replay / CI smoke 에 사용.
#
# 사용:
#   ./scripts/replay-corpus.sh                          # 전체 corpus replay
#   ./scripts/replay-corpus.sh e-axiom/e07              # E7 만
#   ./scripts/replay-corpus.sh auxiliary/aead-aad-19b   # 특정 하위

set -euo pipefail

CORPUS_DIR="test-corpus"
if [[ ! -d "$CORPUS_DIR" ]]; then
  echo "::error::$CORPUS_DIR 부재 — test-corpus 초기화 미완료"
  exit 1
fi

# PROPTEST env 고정 (CI baseline, README §CI fixed seed).
export PROPTEST_CASES="${PROPTEST_CASES:-256}"
export PROPTEST_MAX_SHRINK_ITERS="${PROPTEST_MAX_SHRINK_ITERS:-2048}"
export PROPTEST_RNG_ALGORITHM="${PROPTEST_RNG_ALGORITHM:-xor_shift}"
export PROPTEST_FORK="${PROPTEST_FORK:-1}"

TARGET_SUBPATH="${1:-}"
SEARCH_DIR="$CORPUS_DIR"
if [[ -n "$TARGET_SUBPATH" ]]; then
  SEARCH_DIR="$CORPUS_DIR/$TARGET_SUBPATH"
  if [[ ! -d "$SEARCH_DIR" ]]; then
    echo "::error::$SEARCH_DIR 부재 — axiom_id 경로 확인"
    exit 1
  fi
fi

# axiom_id 경로 → proptest 가 기대하는 crate/.proptest-regressions/<module>.txt 로
# 매핑하여 replay. Case 파일의 `# impacted-crate:` metadata 로 target crate 확정.

case_count=0
while IFS= read -r -d '' corpus_file; do
  # Metadata 에서 impacted-crate 추출.
  crate=$(grep -m1 '^# impacted-crate:' "$corpus_file" | sed 's/^# impacted-crate:[[:space:]]*//' || true)
  if [[ -z "$crate" ]]; then
    echo "warning: $corpus_file — impacted-crate metadata 부재, skip"
    continue
  fi
  # impacted-crate 에 module path 포함 가능 (예: arkhe-forge-core::activity).
  crate_name="${crate%%::*}"
  module_path="${crate#"$crate_name"}"
  module_path="${module_path#::}"
  module_path="${module_path//::/-}"

  target_dir="$crate_name/.proptest-regressions"
  mkdir -p "$target_dir"
  # proptest regressions 파일 은 module 단위 — 단순히 fn name 을 파일명으로.
  cp "$corpus_file" "$target_dir/${module_path:-lib}.txt"
  case_count=$((case_count + 1))
done < <(find "$SEARCH_DIR" -name "*.case" -not -name "README*" -print0)

if [[ $case_count -eq 0 ]]; then
  echo "corpus 가 비어있음 — property test regression case 누적 후 채워집니다."
  exit 0
fi

echo "Replaying $case_count case(s)..."

# Replay — impacted-crate 전체 test (axiom_id 기준 경로라 여러 crate 가능).
if [[ -n "$TARGET_SUBPATH" ]]; then
  # Specific subpath — 관련 crate 만 replay (metadata 로 확정된 crate).
  cargo test --workspace
else
  cargo test --workspace
fi

echo "Regression corpus replay OK — $case_count case(s)."
