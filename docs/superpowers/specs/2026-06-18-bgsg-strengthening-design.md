# Stage A1 — `feat/bgsg-experiment` 보강안 설계 문서 (v2)

- **날짜:** 2026-06-18 (v2 revise)
- **대상 브랜치:** `feat/bgsg-experiment` (HEAD: `a5ee687`)
- **기준선:** `main` (HEAD: `8c3aee3`)
- **단계:** A1 (독립 강화) — 후속으로 A2(sparse), B(통합)가 예정됨
- **v2 변경:** 5인 리뷰(architect/critic/scientist/security/OMC)에서 발견된 Critical 5건 + High 7건 반영. 청크-격리 lemma 도입, Phase 5 ITERATIONS=10 비용 모델 통합, P1 2-pass 키 생성 명세, 노이즈 단정의 가설 전환, ε-equivalence 회귀 재정의, PIR 위협모델 caveat, E17 (Phase 5 shared Evaluator) 추가, E13 wrap-around 정밀화.

---

> **Caveat — Threat Model & Reporting Honesty.** 본 spec의 측정은 **server가 secret_key를 보유하는 단일-당사자 환경**에서 수행된다. Phase 5의 `decrypt → re-encrypt` 루프(`CipherRank.cpp:622-625`)는 실제 PIR 프로토콜의 비유가 아니라 noise budget 회복을 위한 단순화이다. 따라서 본 spec의 wall-clock 측정값은 **"BSGS 알고리즘과 OMP 병렬화의 성능 하한"** 으로 해석되어야 하며, 실배포 PIR(클라이언트가 secret_key 단독 보유, 동형 normalization 필요)의 wall-clock과는 다르다. 격차의 정량화는 별도 spec(`O5` 참조)의 책임이다.

---

## 1. 본 브랜치가 공격하는 병목

`main`의 Phase 3 `ExtractBlindSubgraph`는 N개의 비영(非零) 대각선마다 **단일 ciphertext rotation + plain multiplication + accumulation**을 순차 수행한다. CKKS rotation은 SEAL의 가장 비싼 동형 연산 중 하나(키스위칭 포함)이므로 Phase 3의 wall-clock 비용은 본질적으로 `O(N · T_rot)`에 지배된다. 본 브랜치는 **rotation 횟수 자체를 줄이는** 알고리즘적 변경(Baby-Step Giant-Step, 이하 BSGS)과 **남은 rotation을 병렬화** 하는 시스템적 변경을 결합한다.

### 1.1 변경 영역 요약

| 위치 | 변경 | 영향 |
|---|---|---|
| `BsgsDiag {i, j, plain}` (line 49) | 1D 대각선 → 2D `(i, j)` baby/giant 분해 | Phase 3/5 인터페이스 변경 |
| `FindOptimalAsymmetricBSGS(N, w)` (line 81) | 비대칭 `(m1, m2)` 자동 탐색, 비용 = `m1 + w · m2` | rotation 수 `O(N) → O(m1+m2)` |
| `create_galois_keys(galois_steps, …)` (line 244) | 모든 step `1..nGlobal` 명시 생성 | 임의 BSGS step 지원, **galois key 메모리 O(N)으로 증가** |
| `PreparePublicData` 의 `row < nGlobal*2` (line 353) | Duplicate Padding | Giant-step 회전 시 슬롯 경계 보호 |
| Phase 3 OMP + thread-local `Evaluator` (line 407-409) | 청크 단위 병렬 추출 | wall-clock `~1/T_omp` |
| Phase 5 런타임 cost weight 측정 (line 549-575) | 더미 ciphertext rotation 시간으로 `giant/baby` 비율 추정 | Phase 5 BSGS auto-tune의 입력 |
| Phase 4 결정론적 정렬 + 라운딩 양자화 (line 486-491) | CKKS 노이즈로 인한 순위 비결정성 완화 | BSGS의 부수 효과 보정 |
| Phase 5 OMP block (line 582-684) | **Evaluator/Encryptor/Decryptor/Encoder가 shared** | 데이터 레이스 위험 (E17 참조) |

### 1.2 본 spec이 보고하는 것 vs. 보고하지 않는 것

**보고:** BSGS 알고리즘 변경의 rotation 수 감소, 그로 인한 wall-clock 감소, CKKS 노이즈 영향, OMP 청크 병렬화 효과, Phase 5 단순화 하 측정.

**보고하지 않음 (별도 spec 영역):**
- 실배포 PIR 프로토콜(클라이언트-서버 분리)의 wall-clock
- 동형 normalization 비용 (Phase 5 `decrypt→re-encrypt` 제거 후)
- bootstrapping 영향
- graph-private 모델 (현재는 graph plaintext 가정)

---

## 2. 복잡도 및 자원 모델

기호: N = nGlobal, n = nSub, K = num_chunks, P = OMP 스레드 수, D = 비영 대각선 수, I = `ITERATIONS = 10` (line 538).

### 2.1 Phase 3 비용 — Per-Chunk 단일 호출 (한 번만 실행)

- **Rotation 수 (per chunk):**
  - Baseline (`main`): D개의 임의 step rotation = `D`
  - bgsg: `(m1 − 1)` baby rotation + `(m2 − 1)` giant rotation = `m1 + m2 − 2`
  - 비용비: `D / (m1 + m2 − 2)`. 
    - **Dense regime** (D ≈ N, m1=m2=√N): 비용비 `≈ √N / 2`. **이 규모는 baseline 가정의 상한**이며 A2/sparse 브랜치 통합 후 D ≪ N 인 경우 비용비가 1 이하로 떨어질 수 있음 — 엣지 E11 참조.
- **Plain-mult 수:** D (양쪽 동일)
- **Mod-switch / rescale 수:** D (양쪽 동일)
- **Multiplicative depth:** 1 (양쪽 동일)
- **메모리:** `+m1 · |ct|` (baby_steps 저장). 멀티 스레드(P): `+P · m1 · |ct|`

### 2.2 Phase 5 비용 — Per-Chunk × I Iteration (Power Iteration)

`CipherRank.cpp:538`의 `ITERATIONS=10`을 명시적으로 포함:

```
T_phase5 = I · ( (m1 − 1)·T_rot_baby
              + (m2 − 1)·T_rot_giant
              + D·T_mult
              + D·T_rescale
              + T_decrypt + T_encrypt )    [per chunk]
```

**핵심 함의:**
- Phase 5는 매 iteration마다 `cipherV` 를 새로 암호화(line 622-625) → baby_steps 재계산. **baby_steps 사전계산이 매 iteration 반복**되므로 I배 누적.
- `T_decrypt + T_encrypt` 가 추가됨 → 본 spec의 cap (caveat 박스 참조).
- 실측 wall-clock의 dominant term이 Phase 3 단일 호출이 아니라 **Phase 5 × I** 일 가능성이 크다. 측정 보고는 Phase 1/3/5를 분리해야 함.

### 2.3 Galois Key 비용 — 정량 추정

키 1개당 메모리 ≈ `RNS_prime_count · poly_modulus_degree · 8 bytes · 2`. coeff_modulus = `{60,45,45,60}` → 4 primes. poly=8192 → 1개 ≈ **512 KB**.

| nGlobal | poly_degree | 키 개수 (1..N) | 메모리 (MB) | 생성 시간 추정 |
|---:|---:|---:|---:|---:|
| 256 | 8192 | 256 | ~128 | 수 초 |
| 512 | 8192 | 512 | ~256 | ~10s |
| 1024 | 8192 | 1024 | ~512 | ~30s |
| 2048 | 16384 | 2048 | ~4096 (≈ 4 GB) | ~분 |

P1 (Galois Key Slimming) 후 키 개수가 `m1 + m2 ≈ 2√N`로 축소 → nGlobal=1024 기준 ~32MB (16배 감소).

### 2.4 Slot Utilization

- Baseline: 각 청크가 N 슬롯 사용, `pirBlockSize = 2N`
- bgsg: padding으로 청크 `2N` 슬롯 전체 사용 (값은 중복)
- batch_size 계산식 동일 → 패킹 효율 회귀 없음

---

## 3. 정확성 모델 — bgsg가 baseline과 동등한 출력을 내는 조건

### 3.1 등가성 조건 (C1–C7)

baseline의 출력:
```
y[s] = Σ_d (rot(x, d)[s]) · diag_d[s]
```
bgsg는 `d = j·m1 + i` 분해 후:
```
y[s] = Σ_j rot( Σ_i rot(x, i)[s] · padded_diag_{i,j}[s] , j·m1 )
```

**조건:**
- **(C1) Cyclic rotation:** SEAL CKKS의 rotation은 slot_count 단위 cyclic. ✓
- **(C2) Giant step bound:** `(m2 − 1)·m1 ≤ N − 1` 이어야 함. `m2 = ⌈N/m1⌉` 으로 항상 만족. ✓
- **(C3) Padding 충분성:** 청크 c는 슬롯 `[c·2N, (c+1)·2N)` 전체에 대해 line 353의 인덱싱으로 채워짐. rotation by `j·m1 ∈ [0, N)` 후 청크 c의 비영 영역이 baby step rotation이 가져올 영역을 모두 포함.
- **(C4) 청크-간 의미적 등가성 (Lemma — *Homomorphic Pattern Invariance under Chunk-Translation*).** *Statement:* 모든 청크 c, c′ 에 대해 인코딩 패턴 `diag[c·2N + row] = diag[c′·2N + row]` (단, c < num_targets, c′ < num_targets 영역 내). *Proof sketch:* line 354-355의 `orig_row` 계산은 c에 의존하지 않으므로 모든 c에 동일한 함수값을 채워 넣는다. 따라서 rotation by `j·m1` 후 청크 c의 슬롯 `[c·2N + j·m1, c·2N + j·m1 + 2N)` 가 청크 c+1의 head 영역과 **물리적으로 overlap** 하더라도, **각 슬롯 위치의 값이 동일한 패턴 함수**이므로 의미적 일치는 보존된다. □
  
  *주의:* 이 lemma는 A2/sparse 브랜치가 청크-간 인코딩 패턴을 깨지 않는 한 유지된다. 만약 sparse 브랜치가 청크별로 zero 영역을 다르게 채우면(예: target 의존 sparsity), 본 lemma는 깨지므로 **B 단계에서 재검증 필요**.
- **(C5) 무회전 baby step:** `baby_steps[0] = cipherChunks[k]` (line 412). ✓
- **(C6) Identity giant step guard:** `if (j > 0)` (line 443, 654) — `rotate_vector(..., 0, ...)`은 SEAL에서 throw하므로 `j=0` 분기는 호출 회피. 향후 refactor 시 이 가드 유지가 필수 invariant.
- **(C7) Slot tail 안전성:** `slot_count` 가 `pirBlockSize` 의 정수배가 아닌 경우, 마지막 청크 뒤의 잔여 슬롯은 0으로 인코딩되며 rotation 시 첫 청크의 영역으로 wrap-around. **(가) zero가 첫 청크로 들어옴 → 영향 없음**, **(나) 첫 청크 데이터가 마지막 청크 뒤 잔여로 이동 → 사용되지 않으므로 무해**. 단, `num_chunks = batch_size` (마지막까지 가득) 시 (나)가 다음 청크로 wrap 되어 누설 가능 — `slot_count ≥ num_chunks · pirBlockSize` 임을 코드 line 318에서 보장 (`batch_size = slot_count / pirBlockSize`). ✓

### 3.2 노이즈 영향 — **가설 (R1 측정 대상)**

이전 v1은 "bgsg가 baseline 대비 노이즈 측면에서 동등 또는 우수해야 한다"고 단정했으나, 이는 검증 대상의 선점이었다. v2에서는 **측정 가설**로 재정의:

- **H_noise:** `max_s |decrypt(y_baseline)[s] − decrypt(y_bgsg)[s]| < ε_R1` (ε는 noise floor 기반, sec 7.R1 참조).
- **이론적 출처:** coeff_modulus `{60,45,45,60}` 의 useful level은 2. baseline은 fresh ciphertext 위 rotation, bgsg의 giant rotation은 `rescale_to_next_inplace` (line 429) 후의 ciphertext 위 rotation. **Rotation 노이즈는 level에 의존**하므로 두 방식의 노이즈 항이 동일하지 않다.
- **검증 절차:** sec 7 R1.
- **해석 가이드:** 만약 R1을 위반하면 (i) 본 spec의 cost model 가정 오류, (ii) C4 lemma의 padding 패턴 분석 오류, (iii) C7 wrap-around 가정 오류 중 하나. 이 분류를 따라 root cause로 진입.

### 3.3 Phase 4 보조 변경(라운딩·결정론 정렬)의 분리

라운딩 양자화(`round(val·1e5)/1e5`, line 486)와 결정론 정렬(lex tie-break, line 491)은 **bgsg와 독립적인 개선**이며, sec 6.1 비교군에서 **ablation으로 별도 분리** 측정한다. 임계값 `1e5` vs `1e-6` 의 10× 불일치(양자화 grain이 비교 grain보다 거침)는 의도된 것인지 확인 필요 — sec 4.E18 참조.

---

## 4. 엣지 케이스 카탈로그

| ID | 케이스 | 현재 거동 | 위험도 |
|---|---|---|---|
| **E1** | `m1 = 1` (Auto-Tune 극단) | weight=1.0에서는 절대 선택 안 됨(증명: 비용 `1 + 1·N = N+1` > `√N + √N = 2√N`). weight ≥ N에서만 선택 가능. cap=5.0 (line 571)으로 효과적 차단 | **낮음** (수학적으로 cap이 보호) |
| **E2** | `m1 = N` | weight가 매우 클 때 선택. nSub=256, poly=8192 → m1=256 ciphertext (~128MB). cap=5.0 하에서는 미선택 | **낮음** (cap에 의해 보호) |
| **E3** | `m2 = 1` | giant rotation 0회, 모든 d가 i = d, j = 0. padding region 미사용 | 낮음 |
| **E4** | OMP 스레드 간 `galois_keys` 동시 read | SEAL `GaloisKeys` thread safety 미문서 | **중간**: TSan으로 검증, suppress 리스트 사전작성 |
| **E5** | OMP 스레드별 `Evaluator` 생성 (Phase 3만) | SEAL `shared_ptr<SEALContext>` 공유 read-only OK | 낮음 |
| **E6** | Auto-Tune 측정 noise | wall-clock jitter | **중간**: P2로 해결 |
| **E7** | Auto-Tune step=16 하드코딩 (line 564) | 실제 giant step `m1` 과 다름 | **중간**: P2로 해결 |
| **E8** | Phase 3 weight=1.0 고정 (line 182), Phase 5만 measurement | 일관성 결함 | **중간**: P3로 해결 |
| **E9** | `nGlobal` 대규모 (4096) → galois key O(N) | 초기화 시간 + 메모리 폭증 | **높음**: P1로 해결 |
| **E10** | Empty chunk | `ceil(num_targets/batch_size)`는 `num_targets % batch_size = 0` 시 추가 청크 생성 안 함 | **없음** (v1 오류 정정) |
| **E11** | `D < m1 + m2 − 2` (sparse 그래프) | bgsg의 rotation 수 > plain-mult 수 → 역효과. **A2/sparse 통합 시 핵심** | 낮음 (A1 단독 무관) |
| **E12** | Sparse 브랜치 통합 시 zero padding이 C4 lemma 깨뜨림 | B 단계 위험 | **중간**: B에서 재검증 |
| **E13** | Last-chunk slot tail wrap-around | C7 조건 하에 안전 (sec 3.1 C7 분석) | 낮음 (C7로 해결) |
| **E14** | CKKS scale drift (`scale()=scale` 강제 후 add) | baseline과 동일 | 낮음 |
| **E15** | `real_weight` clamp `[1.0, 5.0]` | E1/E2의 m1 극단을 차단하는 silent safety. 그러나 assertion/warn 없음 | **중간**: clamp 발동 시 로그 출력 권장 |
| **E16** | dummy_cipher = fresh ciphertext, 실제 BSGS는 mid-level | weight 측정 비현실 | **중간**: P2 (4) — `mod_switch_to_next_inplace(dummy)` 1회 후 측정 |
| **E17** | **Phase 5 OMP block 내부 shared `evaluator`/`encryptor`/`decryptor`/`encoder`** | line 583 `#pragma omp parallel for` 내부에서 line 623, 625, 630, 642, 666이 멤버 포인터를 공유 호출. SEAL `Encryptor`는 내부에 PRNG 상태 보유 → **데이터 레이스 + silent incorrect trust score** | **높음**: 코드 패치로 즉시 해결 |
| **E18** | Phase 4 양자화 grain `1e-5` vs 비교 grain `1e-6` 10× 불일치 | 양자화 후 tie-break이 사실상 무의미 (양자화 grain이 비교보다 큼) | **중간**: grain 일치화 또는 분리된 정당화 필요 |

---

## 5. 강화안

### 5.1 [P1] Galois Key Slimming — **2-Pass 키 생성 명세 (의존 cycle 해결)**

- **가설:** 실제 사용 step은 `S_pir = {1..m1−1} ∪ {m1, 2m1, …, (m2−1)m1}` (Phase 3, N=nGlobal) 와 `S_pr = {1..m1'−1} ∪ {m1', 2m1', …, (m2'−1)m1'}` (Phase 5, N=nSub). 두 집합의 합집합만 생성하면 키 수가 `O(N) → O(√N + √n)` 로 감소.
- **의존 cycle 해결 — Two-Pass Key Generation:**
  ```
  Pass 1 (Bootstrap measurement):
    - Galois keys: S_boot = {1, ⌊√N⌋, ⌊√n⌋}  (단 3개)
    - Measure baby/giant rotation cost on dummy ciphertext
    - real_weight = T_giant / T_baby (워밍업 3회 + 중앙값 5회, P2 적용)
  Pass 2 (Production):
    - m1_pir, m2_pir = FindOptimalAsymmetricBSGS(N, real_weight)
    - m1_pr,  m2_pr  = FindOptimalAsymmetricBSGS(n, real_weight)
    - S_prod = S_pir(m1_pir, m2_pir) ∪ S_pr(m1_pr, m2_pr)
    - Discard Pass 1 keys, regenerate galois_keys with S_prod
  ```
- **Pass 1 비용:** 3개 키 생성 ≈ 1.5MB, < 1초. 무시 가능.
- **변경 위치:** `InitializeFHE()` line 244-246, `RunPipeline()` line 175-186.
- **측정 메트릭:** `galois_keys` 직렬화 사이즈 (MB), 총 init time (Pass 1 + Pass 2 + 측정), peak RSS.
- **위험:** Pass 2 키 생성이 Pass 1 키 폐기 후 재할당이므로 transient memory peak가 두 키셋의 합. 큰 N에서 peak RSS 일시 증가.

### 5.2 [P2] Auto-Tune Robustness — 워밍업·다중 샘플·정확한 step·level matching

- **가설:** 단일 샘플 + step=16 하드코딩 + fresh level 측정의 분산 문제 해결.
- **변경 내용:**
  1. 워밍업 3회 (측정 제외)
  2. baby/giant 각 5회 측정 후 중앙값
  3. giant 측정 step = `⌊√n⌋` (Pass 1 시점, Pass 2 step과 일치 보장 위해)
  4. 측정 ciphertext의 level을 BSGS 실제 사용 level과 일치 — **구체 패턴:**
     ```cpp
     Ciphertext dummy_for_measure;
     encryptor->encrypt(dummy_plain, dummy_for_measure);
     evaluator->mod_switch_to_next_inplace(dummy_for_measure);  // level L-1
     ```
- **사전 실험:** `real_weight` 의 1-sample 분산 측정 → N (반복수)을 CV<10% 보장으로 도출. 5회는 잠정 default.
- **변경 위치:** Phase 5 line 549-575를 `MeasureRotationWeight()` 헬퍼로 추출.
- **측정 메트릭:** 5 run의 `real_weight` 표준편차, 동일 입력에서 (m1, m2) 결정 일관성, **사전 실험: 1-sample variance histogram**.

### 5.3 [P3] 통합 Cost Model — Phase 3도 measurement 사용

- **가설:** Phase 3 weight=1.0 고정은 임시. P2의 weight를 Pass 1 직후 한 번 측정해서 **Phase 3와 Phase 5 모두 동일 weight** 사용.
- **변경 위치:** `RunPipeline()` Pass 1 직후 (P1과 통합).
- **부수 효과:** Phase 3 (m1, m2) 가 실제 시스템에 맞춰 조정.

### 5.4 [P4] Cost Function 일반화 — Plain-mult + ITERATIONS 포함

- **가설:** 현재 cost `m1 + w·m2` 는 plain-mult와 Phase 5 iteration 누적을 무시. 일반화:
  ```
  cost(m1, m2; D, I_factor) = m1·T_rot + (m2 − 1)·T_giant
                            + D·T_mult + D·T_rescale         (Phase 3)
  + I · (m1·T_rot + (m2 − 1)·T_giant + D·T_mult + D·T_rescale + T_enc + T_dec)  (Phase 5)
  ```
- **선결 조건:** Phase 3 호출 시점에 D 추정치 필요. PreparePublicData 가 비영 대각선 수를 반환.
- **메모:** B 단계에서 sparse 브랜치와 결합 시 결정적으로 중요. A1 단독 적용 시 효과 제한적.

### 5.5 [P5] Thread-safety 검증 — TSan + 코드 패치 (E17 해소)

- **5a. 코드 패치 (선행, Critical 차단):** Phase 5 OMP block (line 582-684) 내부에서 멤버 `evaluator`/`encryptor`/`decryptor`/`encoder`를 호출하는 모든 위치를 **thread-local 인스턴스**로 교체. Phase 3의 line 409 패턴 적용.
  ```cpp
  #pragma omp parallel for
  for (int k = 0; k < num_chunks; k++) {
      Evaluator   thr_eval(*context);
      Encryptor   thr_enc(*context, public_key);  // public_key 보관 필요
      Decryptor   thr_dec(*context, secret_key);  // secret_key 보관 필요
      CKKSEncoder thr_encoder(*context);
      // ... use thr_* instead of this->evaluator etc.
  }
  ```
  **주의:** `public_key`, `secret_key` 가 현재는 InitializeFHE local. 클래스 멤버로 승격 필요. **단일-당사자 측정 환경 caveat에 따라 secret_key 보관은 본 spec 범위 내.**
- **5b. TSan 검증:** CI에 TSan 빌드 추가. SEAL 내부의 known false positive를 위한 suppress 리스트 사전 작성:
  - `KeyGenerator` 내부 PRNG (single-init)
  - `MemoryPoolHandle` 의 atomic ref count (벤치마크 환경에서만 의미)
- **위험:** TSan false positive 폭주 가능 → SEAL upstream issue 참조.

### 5.6 [P6 — 별도 spec, A1 범위 밖] Baby Step Re-use Across Iterations

- coeff_modulus `{60,45,45,60}` 의 useful depth = 2 < required depth = I · 1 = 10. **decrypt → re-encrypt 없이는 작동 불가**(sec 8 O5에서 형식화). 따라서 P6는 coeff_modulus 재설계와 함께 별도 spec.

---

## 6. 측정 계획 (사전 정의, 사후 cherry-pick 방지)

### 6.1 비교군 — Ablation 분리

| ID | 구성 | 검증 |
|---|---|---|
| C0 | `main` baseline | reference |
| C1 | bgsg full | end-to-end |
| C2 | bgsg − Phase 4 quantization | Phase 4 효과 분리 (D6 SRP) |
| C3 | bgsg + P1 | galois key 메모리 |
| C4 | bgsg + P1 + P2 | auto-tune 분산 |
| C5 | bgsg + P1 + P2 + P3 | Phase 3 weight unification |
| C6 | bgsg + P1 + P2 + P3 + P4 | cost model 일반화 |
| C7 | bgsg + P5a (코드 패치) | Phase 5 race 제거 |

### 6.2 Sweep 파라미터 — **축소 정책**

전체 sweep 6,720 runs (≈ 42일)이 비현실적. **2단계 sweep:**

- **Coarse (3 cells, N=10 반복):** `(nGlobal, nSub, num_targets, OMP) ∈ {(256, 64, 4, 4), (1024, 256, 16, 4), (2048, 256, 16, 8)}`. 모든 C0~C7. 총 240 runs.
- **Fine (선택 cell, N=5 반복):** Coarse에서 효과가 가장 큰 cell의 nGlobal × OMP 면만 full factorial. `nGlobal ∈ {256, 1024, 2048}` × `OMP ∈ {1, 2, 4, 8}` × C0~C7 × N=5 = 480 runs.

**총 720 runs.** 단위 추정 30~120초 → 6~24시간. 단일 머신 1일 내 가능.

### 6.3 메트릭

| 카테고리 | 메트릭 | 단위 |
|---|---|---|
| 시간 | InitializeFHE wall-clock (P1 적용 시 Pass 1 + Pass 2 분리) | sec |
| 시간 | Phase 1, 3, 5 wall-clock (Phase 5는 per-iteration도 보고) | sec |
| 시간 | Rotation 단위 시간 (warmup 후 중앙값) | ms |
| 메모리 | `galois_keys` 직렬화 크기 | MB |
| 메모리 | Peak RSS (Pass 1, Pass 2 분리) | MB |
| 정확도 | `max_s |y_base[s] − y_bgsg[s]|` (Phase 3 출력) per target | abs |
| 정확도 | `|fheScore − groundTruthScore|` per target | abs |
| 정확도 | Top-K Kendall's τ (K = min(nSub, 10)) vs 평문 PageRank | -1~1 |
| 정확도 | Top-K 일치율 (K = nSub) | 0~1 |
| 결정성 | 동일 seed 10회 실행 출력의 max pairwise difference | abs |

### 6.4 통계 프로토콜

- 조합당 **N = 5회** (fine) / **N = 10회** (coarse) 실행
- 시간 메트릭: **중앙값 + IQR + 95% bootstrap CI**
- 정확도 메트릭: **중앙값 + max + 95th percentile + 분포 히스토그램**
- 비교: **Wilcoxon signed-rank** (비모수, N 작음). 다중 비교: **Benjamini-Hochberg FDR 5%**.
- Effect size: **log₂(median(C_i) / median(C0))** for 속도 메트릭.

### 6.5 환경 고정 + 재현성

- CPU governor `performance`, OMP_PROC_BIND=close, OMP_PLACES=cores
- 빌드 매니페스트 JSON 자동 저장: `{cmake_version, compiler_version, SEAL_commit, kernel, transparent_hugepages_state, csv_sha256}`
- **데이터셋 SHA-256 검증** (코드 시작 시 체크)
- SEAL `UniformRandomGeneratorFactory::DefaultFactory()` 를 seeded 버전으로 교체. seed = `(experiment_id, trial_no)` 의 해시.
- `unordered_map` 순서 비결정성: Phase 1의 `globalNodeToIndex` 구성 후 `sort` 한 결정론 순서 강제.
- 실험 순서 무작위화 (thermal/cache bias 방지).
- 조건 블록 사이 60초 idle.

---

## 7. 정확성 회귀 테스트

### R1 (ε-equivalence): Phase 3 출력의 노이즈 bound

`max_s |decrypt(y_baseline)[s] − decrypt(y_bgsg)[s]| < ε_R1`

**ε_R1 의 근거:** scale=2⁴⁵, level=1 decrypt 후 CKKS noise floor 실측치 (사전 실험으로 측정). 임의값 1e-4 가 아니라 **floor × 100~1000** 마진으로 설정. 사전 실험 결과를 spec에 갱신.

### R2 (Single-thread ε-equivalence): m1=1, m2=N 조건

- **OMP=1 단일 스레드, m1=1, m2=N** 에서 `max_s |y_base[s] − y_bgsg[s]| < 10⁻⁸`.
- **v1의 "bit-for-bit" 단정은 폐기.** 이유: bgsg의 `multiply→rescale→scale=scale→mod_switch→add` 순서가 baseline의 `multiply→rescale→add` 와 floating-point 누적 순서 차이를 만든다.

### R3 (Verdict 일치): Phase 6 APPROVED/REJECTED 결과

- Auto-tune off/on 양쪽에서 동일 verdict. 임계값(`fheScore ≥ 0.0150`, line 699) 근처(threshold ± 10%) 입력에서는 fragile하므로 **threshold 근처 회피 입력**으로 검증.

### R4 (Multi-thread ε-equivalence): OMP=1 vs OMP=4

- bit-for-bit 폐기. `max_s |y_OMP1[s] − y_OMP4[s]| < 10⁻⁸` (per-chunk addition order는 OMP scope이 chunk 단위라 보존됨).
- **부정 테스트:** OMP scope이 j-loop 내부로 확장되는 미래 refactor가 R4를 깨뜨림을 명시 (regression trap).

### R5 (Race-free under stress): OMP {4, 8, 16} 동일 입력 10회

- 출력 ciphertext 의 max pairwise diff < 10⁻⁶. **silent incorrect trust score** 가용성 회귀 검증.

### R6 (Phase 4 grain consistency): 양자화 grain ↔ tie-break grain

- nGlobal ∈ {256, 2048} 에서 top-K 결정성 유지. 임계값을 nGlobal/scale 함수로 파라미터화하는 별도 spec 가능성 명시.

---

## 8. 개방 문제

- **O1:** `D` 의존성을 cost model에 포함했을 때 B 단계 sparse 브랜치와 결합 시 (m1, m2) 선택이 어떻게 달라지는가?
- **O2:** CKKS slot rotation 비용의 level 의존성을 cost model에 어떻게 통합하는가? P2 (4) 가 부분적 해결.
- **O3:** baby_steps lazy 사전계산의 메모리·시간 tradeoff?
- **O4:** `GaloisKeys` thread-safety 공식 문서화 요청 (SEAL upstream issue).
- **O5:** Phase 5 `decrypt→re-encrypt` 제거는 **현재 coeff_modulus 하에서는 불가능**. useful depth = 2 < required depth = 10. 해결안은 (i) coeff_modulus 확장 (~520-bit 이상, security level 검증 필요), (ii) bootstrapping 도입, (iii) iteration 수 감소. **별도 spec 영역**.
- **O6:** Phase 1 의 `O(N³)` M_total 계산이 nGlobal=2048에서 전체 wall-clock의 dominant term이 되는가? A2의 sparse 브랜치가 이를 공격. **A1 단독 측정에서 Phase 분리 보고 필수** — Phase 3만 빨라져도 전체 wall-clock이 Phase 1에 지배될 가능성.
- **O7:** SEAL 16384 poly_modulus_degree에서 `{60,45,45,60}` coeff_modulus는 security level 미달 가능. 자동 확장 코드 line 744-746 검토 필요.

---

## 9. 비-목표 (Non-Goals)

- **NG1.** Phase 1 평문 전처리 비용(O(N³)) — A2/sparse 영역
- **NG2.** CKKS scheme 변경 (BFV 전환, bootstrapping 도입)
- **NG3.** PIR 프로토콜 변경 (round 수, 동형 normalization)
- **NG4. (보안)** Graph-private 모델 — 본 spec은 graph plaintext + target ciphertext 가정. graph-private 확장 시 D-기반 cost model + timing auto-tune 재검토 필요
- **NG5. (보안)** PIR 프로토콜 충실성 측정 — Phase 5는 server-side decrypt→re-encrypt 단순화. 실 PIR wall-clock 격차는 별도 spec
- **NG6. (보안)** Side-channel/timing 분석 — wall-clock 기반 auto-tune의 target 익명성 영향. 단일 머신 시뮬에서 무관
- **NG7. (보안)** Deployment-time galois key 협상 — step set의 client→server 노출(P1 적용 시 fingerprinting surface). 본 spec은 simulation 한정
- **NG8. (정확성)** Phase 4 결정론적 정렬 임계값(1e-6, 1e5 round)의 **보안 속성** 보장은 본 spec 책임 아님 — ranking 무결성 회귀는 별도 spec

---

## 10. 의존성 DAG와 적용 순서

```
P5a (코드 패치, 즉시) ── 독립
       │
       ▼
P1 Pass 1 (seed keys + measure) ── P2 (auto-tune robustness) ── 같이 묶임
       │
       ▼
P3 (통합 cost model, weight 주입)
       │
       ▼
P1 Pass 2 (production galois keys 재생성)
       │
       ▼
P4 (cost function 일반화, D 추정)
       │
       ▼
P5b (TSan + CI 통합)
```

**키 dependency:**
- P1 Pass 1 ← P2 (measurement는 Pass 1 seed 키로 수행)
- P3 ← P2 (weight를 사용)
- P1 Pass 2 ← P3 (m1, m2 확정 후 production 키)
- P4 ← P3 (cost function이 D, weight 동시 입력)
- P5a 는 모든 다른 변경과 독립 — Critical이므로 가장 먼저

**v1의 순서 (P5→P2→P3→P1→P4) 는 self-contradictory** 이었음 — Pass 1/2 분리로 해소.

---

## 11. 엔지니어링 노트 (구 "학술적 기여")

v1의 "학술적 기여" 주장은 prior art (Halevi-Shoup BSGS, Han-Hhan FHE benchmark) 와 중첩되므로 **엔지니어링 관찰**로 재명명:

- **(a)** **시스템 측정 기반 cost model 분해** — rotation/mult/level의 분리 측정과 weight 합산이 시스템마다 (CPU, SEAL 버전, OMP) 다른 (m1, m2) 최적해를 낸다는 관찰. 일반 BSGS 문헌은 `m1+m2` 만 다룸.
- **(b)** **Sampling 분산 문제의 정량화** — 단일 wall-clock 샘플로 결정된 (m1, m2) 가 후속 phase의 정확도/속도에 미치는 영향. 메타-측정 문제 형식화.
- **(c)** **Galois key 비용의 step-set 의존성** — 키 메모리·생성시간이 step set 카디널리티에 정확히 비례한다는 양적 관찰. P1 의 ROI 추정에 사용.
- **(d)** **Phase 추출 노이즈와 Phase 정렬 노이즈의 분리 필요성** — bgsg 브랜치의 보조 변경(Phase 4)이 실제로 해결하는 문제는 BSGS와 무관. ablation 측정(C2)로 분리.

이 항목들은 **본 파이프라인 특수 관찰**이며, 일반 FHE 문헌의 contribution과 구분된다.

---

## 부록 A — 변경 코드 참조 색인

| 라인 | 항목 |
|---|---|
| 49-58 | `BsgsDiag` |
| 63-69 | `BSGSParams` |
| 81-105 | `FindOptimalAsymmetricBSGS` |
| 175-186 | Phase 3 호출 시 weight=1.0 (P3 보강 대상) |
| 235 | coeff_modulus `{60,45,45,60}` (O5/O7 근거) |
| 244-246 | Galois key step 명시 (P1 변경 대상) |
| 266-369 | `PreparePublicData` (padding line 353, C3/C4 근거) |
| 403-460 | `ExtractBlindSubgraph` (OMP line 407, baby loop line 413, giant loop line 420, `j>0` guard line 443) |
| 486-491 | Phase 4 라운딩(1e5) + 결정론 정렬(1e-6) (E18 근거) |
| 538 | `ITERATIONS = 10` (sec 2.2 cost model 근거) |
| 549-575 | Phase 5 weight measurement (E6/E7/E16, P2 변경 대상) |
| 577-579 | Phase 5 auto-tune 호출 |
| 582-684 | **Phase 5 OMP block — shared evaluator/encryptor/decryptor/encoder (E17, P5a 코드 패치 대상)** |
| 588-611 | Phase 5 BSGS diagonal 생성 |
| 622-625 | Phase 5 매 iteration fresh encrypt (sec 2.2 I·(T_enc+T_dec) 근거) |
| 654 | Phase 5 `if (j > 0)` guard (C6 invariant) |
| 699 | trust score threshold `0.0150` (R3 근거) |
| 744-746 | poly_degree 자동 확장 (O7 근거) |

---

## 부록 B — v1 → v2 변경 이력

| v1 위치 | 변경 |
|---|---|
| sec 3.1 C4 | 슬롯 산술 재증명 + Lemma "Homomorphic Pattern Invariance under Chunk-Translation" 도입 |
| sec 3.1 | C6, C7 추가 (identity giant guard, slot tail) |
| sec 3.2 | 노이즈 비교 단정 → 측정 가설 H_noise 로 재정의 |
| sec 2.1 | Phase 5 ITERATIONS=10 비용 누락 → sec 2.2 추가 |
| sec 2.3 | Galois key 메모리 정량 표 추가 |
| sec 4 | E1, E2 risk 재평가 (cap에 의해 낮음); E10 오류 정정; E17, E18 추가 |
| sec 5.1 | P1 의존 cycle 해결 — Two-Pass 키 생성 명세 |
| sec 5.2 | level matching 구체 코드 패턴 명시 |
| sec 5.5 | P5a (코드 패치) 와 P5b (TSan) 분리 |
| sec 5.6 | P6를 별도 spec으로 명시 + coeff_modulus 한계 근거 |
| sec 6 | sweep 축소 정책 (Coarse + Fine), Wilcoxon + Benjamini-Hochberg FDR, seed 고정, CSV SHA-256 |
| sec 7 | R2/R4 bit-for-bit 폐기 → ε-equivalence. R5 (race-free), R6 (grain consistency) 추가 |
| sec 8 | O5 (decrypt 재암호 불가성) 형식화; O6 (Phase 1 dominant), O7 (poly=16384 security) 추가 |
| sec 9 | NG4~NG8 추가 (graph-private, PIR 충실성, side-channel, key 협상, output 임계값) |
| sec 10 | DAG 명시, Pass 1/Pass 2 cycle 해결 |
| sec 11 | "학술적 기여" → "엔지니어링 노트" 재명명, prior art 인정 |
| 캐비엣 | Threat Model & Reporting Honesty 박스 도입 (H1 해소) |
