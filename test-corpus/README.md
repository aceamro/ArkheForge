# ArkheForge Runtime — Property Test Regression Corpus

Property-based test (proptest) 실패 case 의 regression corpus. 발견된 shrink case
를 고정 테스트화하여 동일 case 가 다시 깨지지 않도록 잠가둔다. 디렉터리는
axiom ID 기준으로 구성되어 axiom coverage 추적과 spec ↔ regression 매핑이
직접 된다.

---

## 디렉터리 구조 — axiom_id 기준

```text
test-corpus/
├── README.md                       # 본 문서
├── e-axiom/                        # E1-E13 (E-series axiom)
│   ├── e01-runtime-core-primitive-set/
│   ├── e02-compute-pure/
│   ├── e03-runtime-to-l0-unidirectional/
│   ├── e04-id-uniqueness/
│   ├── e05-immutable-user-shell-id/
│   ├── e06-authenticated-user-binding/
│   ├── e07-shell-isolation-dual-tier/
│   ├── e08-dag-depth/
│   ├── e09-meta-verb-depth/
│   ├── e10-arkhe-uri/
│   ├── e11-cascade-tick/
│   ├── e12-runtime-bootstrap-in-band/
│   ├── e13-signature-class-policy/
│   └── e14-compute-determinism/      # E14 v0.12 도입 — INDEX.md cross-ref to R4-J Subset-Rust dylint tests
├── e-user/                         # E-user-1..4
├── e-actor/                        # E-actor-1..5
├── e-space/                        # E-space-1..7
├── e-entry/                        # E-entry-1..7
├── e-act/                          # E-act-1..7
└── auxiliary/                      # Cross-axiom / non-axiom regression
    ├── typecode-allocation/
    ├── bounded-string-overflow/
    └── aead-aad-19b/
```

### 파일명 규칙

```text
test-corpus/<axiom-bucket>/<axiom-id>/<YYYYMMDD-HHMMSS>-<summary>.case
```

예:
- `test-corpus/e-axiom/e07-shell-isolation-dual-tier/20260424-153000-cross-shell-target.case`
- `test-corpus/e-act/e-act-1-idempotent/20260501-090000-retract-toggle.case`
- `test-corpus/auxiliary/aead-aad-19b/20260601-143000-aad-byte-19-deviation.case`

---

## axiom_id ↔ spec 매핑

| axiom_id 디렉터리 | Spec 위치 | 설명 |
|---|---|---|
| `e-axiom/e01-*` | §11.1 E1 | Core primitive set |
| `e-axiom/e02-*` | §11.1 E2 | Compute pure (A11 승계) |
| `e-axiom/e03-*` | §11.1 E3 | Runtime → L0 단방향 |
| `e-axiom/e04-*` | §11.2 E4 | UserId / ActorId 유일성 |
| `e-axiom/e05-*` | §11.2 E5 | Actor.user_id + shell_id immutable |
| `e-axiom/e06-*` | §11.2 E6 | Authenticated typestate |
| `e-axiom/e07-*` | §11.2 E7 | Shell 격리 dual-tier |
| `e-axiom/e08-*` | §11.3 E8 | DAG depth ≤ 64 |
| `e-axiom/e09-*` | §11.3 E9 | Meta-verb depth ≤ manifest |
| `e-axiom/e10-*` | §11.4 E10 | ArkheUri 3-tuple |
| `e-axiom/e11-*` | §11.4 E11 | Cascade tick |
| `e-axiom/e12-*` | §11.4 E12 | RuntimeBootstrap in-band |
| `e-axiom/e13-*` | §11.4 E13 | SignatureClassPolicy chain-anchored |
| `e-axiom/e14-*` | §11.x E14 (v0.12) | Compute Determinism Closure — R4-J Subset-Rust (E14.L1-Deny) + WASM sandbox (E14.L2-Allow). cross-ref `e-axiom/e14-compute-determinism/INDEX.md` |
| `e-user/e-user-N-*` | §4.1 invariant | User primitive |
| `e-actor/e-actor-N-*` | §4.2 invariant | Actor primitive |
| `e-space/e-space-N-*` | §4.3 invariant | Space primitive |
| `e-entry/e-entry-N-*` | §4.4 invariant | Entry primitive |
| `e-act/e-act-N-*` | §4.5 invariant | Activity primitive |
| `auxiliary/*` | cross-axiom | Wire format / helper / regression 일반 |

신규 axiom 추가 시 본 표 + 디렉터리를 함께 갱신한다.

---

## 저장 규약

### 파일 포맷

Proptest `.proptest-regressions/<module>.txt` format 그대로 사용 — 각 line:

```text
cc <sha256-of-shrunk-case> # shrinks to <human-readable summary>
```

추가 metadata 는 `# ` 접두로 파일 상단에 배치 (proptest parser 는 `#` 주석 무시):

```text
# axiom: E7
# spec-ref: runtime-book/src/architecture/runtime-spec.md §11.2
# discovered: 2026-04-24T15:30:00Z
# discovered-by: ci-smoke (PR #123)
# impacted-crate: arkhe-forge-core::activity
# (proptest format follows)
cc 8f3a...c02b # shrinks to Activity { shell_id: ..., target: Activity(..) }
```

### Git LFS vs inline

- 각 `.case` 파일 < **10 KB** — inline commit.
- ≥ 10 KB 시 `git-lfs track "test-corpus/**/*.case"` 검토.

현재 corpus 전체 크기는 < 10 MB 로 예상 — inline 관리 가능.

---

## Corpus 갱신 절차

1. 로컬 `cargo test --features proptest-unstable` 실행.
2. 실패 case 발견 시 proptest 가 `.proptest-regressions/<module>.txt` 자동 기록.
3. 해당 내용 을 **axiom_id 기준 경로** 로 copy — metadata block 추가:

   ```text
   # axiom: E7
   # spec-ref: §11.2
   # discovered: <ISO-8601>
   # impacted-crate: <crate::module>
   cc <hash> # shrinks to <summary>
   ```

4. `test-corpus/<axiom-bucket>/<axiom-id>/` 에 commit.
5. 다음 CI run 에서 `scripts/replay-corpus.sh` 가 regression case 를 fixed seed 로 재실행.

---

## CI fixed seed

CI 환경변수 고정:

```yaml
env:
  PROPTEST_CASES: 256
  PROPTEST_MAX_SHRINK_ITERS: 2048
  PROPTEST_SEED: "arkhe-forge-runtime"     # 고정 seed
  PROPTEST_RNG_ALGORITHM: "xor_shift"      # deterministic rng
  PROPTEST_FORK: "1"                       # 개별 case isolate
```

로컬 개발 시 `export PROPTEST_CASES=4096` 등 override 가능 (CI baseline 불변).

---

## Replay 명령

`scripts/replay-corpus.sh` — regression corpus 재실행 (전체 property test 전에
선제 검증):

```bash
./scripts/replay-corpus.sh                          # 전체
./scripts/replay-corpus.sh e-axiom/e07              # E7 만
./scripts/replay-corpus.sh auxiliary/aead-aad-19b   # 특정 하위
```

---

## 정책 (append-only)

- Regression case **삭제 금지** — 근본 원인 해결되어도 case 유지 (재발 탐지).
- Case 파일 이름 변경 시 `git mv` 로 history 보존.
- Axiom 번호 재할당 / 삭제는 spec DIP round 에서만 허용.
- Axiom_id 디렉터리 rename 은 **금지** — 기존 reference 모두 갱신 필수 (비용 과다).
- 본 README 정책 변경은 theorist approval PR 의무.
