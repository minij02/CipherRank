# Stage A1 — `feat/bgsg-experiment` 보강안 설계 문서

- **날짜:** 2026-06-18
- **대상 브랜치:** `feat/bgsg-experiment` (HEAD: `a5ee687`)
- **기준선:** `main` (HEAD: `8c3aee3`)
- **저자:** CipherRank 팀
- **단계:** A1 (독립 강화) — 후속으로 A2(sparse), B(통합)가 예정됨

---

## 1. 본 브랜치가 공격하는 병목

`main`의 Phase 3 `ExtractBlindSubgraph`는 N개의 비영(非零) 대각선마다 **단일 ciphertext rotation + plain multiplication + accumulation**을 순차 수행한다. CKKS rotation은 SEAL의 가장 비싼 동형 연산 중 하나(키스위칭 포함)이므로 Phase 3의 wall-clock 비용은 본질적으로 `O(N · T_rot)`에 지배된다. 본 브랜치는 **rotation 횟수 자체를 줄이는** 알고리즘적 변경(Baby-Step Giant-Step, 이하 BSGS)과 **남은 rotation을 병렬화** 하는 시스템적 변경을 결합한다.

### 1.1 변경 영역 요약

| 위치 | 변경 | 영향 |
|---|---|---|
| `BsgsDiag {i, j, plain}` 구조체 (line 49) | 1D 대각선 인덱스 `d` → 2D `(i, j)` baby/giant 분해 | Phase 3/5 인터페이스 변경 |
| `FindOptimalAsymmetricBSGS(N, w)` (line 81) | 비대칭 `(m1, m2)` 자동 탐색, 비용 = `m1 + w · m2` | rotation 수 `O(N) → O(m1+m2)` |
| `create_galois_keys(galois_steps, …)` (line 244) | 모든 step `1..nGlobal` 명시 생성 | 임의 BSGS step 지원, **galois key 메모리는 증가** |
| `PreparePublicData` 의 row 루프 `< nGlobal*2` (line 353) | Duplicate Padding | Giant-step 회전 시 슬롯 경계 보호 |
| Phase 3 OMP + thread-local `Evaluator` (line 407-409) | 청크 단위 병렬 추출 | wall-clock `~1/T_omp` (T_omp = OMP 스레드 수) |
| Phase 5 런타임 cost weight 측정 (line 549-575) | 더미 ciphertext rotation 시간으로 `giant/baby` 비율 추정 | Phase 5 BSGS auto-tune의 입력 |
| Phase 4 결정론적 정렬 + 라운딩 양자화 (line 486-491) | CKKS 노이즈로 인한 순위 비결정성 완화 | 단, BSGS의 부수 효과 보정용 |

---

## 2. 복잡도 및 자원 모델

### 2.1 Phase 3 비용 — Rotation·Mult·Mod-switch 분리

기호: N = nGlobal, K = num_chunks, P = OMP 스레드 수, D = 비영 대각선 수(`|pirDiagonals|`).

- **Rotation 수 (per chunk):**
  - Baseline (`main`): D개의 임의 step rotation = D
  - bgsg: `(m1 − 1)` baby rotation + `(m2 − 1)` giant rotation = `m1 + m2 − 2`
  - 약식 비용비: `D / (m1+m2−2)`. m1=m2=√N일 때 약 `D/(2√N − 2)` 개선. D ≈ N일 경우 `√N/2` 배.
- **Plain-mult 수:** D (양쪽 동일). bgsg의 baby_step 사전계산이 추가되므로 multiply_plain의 **순서**만 달라진다.
- **Mod-switch / rescale 수:** D (양쪽 동일).
- **Multiplicative depth:** baseline은 (rot → mult → rescale) 1-depth. bgsg는 baby-step에 추가 rotation이 선행되지만 mult-depth는 1로 동일. **noise 예산 사용량은 큰 차이 없음**(rotation은 noise를 키스위칭 텀만 추가).
- **메모리:** baby_steps 벡터가 `m1` 개의 ciphertext를 추가로 보유 → `+m1 · |ct|`.

### 2.2 OMP 병렬화 효과

이상적 wall-clock = `(m1 + m2 − 2) · T_rot + D · T_mult` per chunk, K개 청크가 P 스레드에 분산되므로 총 `⌈K/P⌉ · …`. OMP 스레드는 `omp_set_num_threads(4)`로 4 고정(main.cpp line 714).

### 2.3 Galois Key 비용 (회귀 주의)

- Baseline: 기본 `create_galois_keys()` → power-of-2 step만 ⇒ key 개수 `≈ log₂(N)`
- bgsg: `1..N` 모두 ⇒ key 개수 `≈ N`

→ **galois_keys 메모리/생성시간은 `O(log N) → O(N)` 으로 증가**한다. 이는 의도된 trade-off가 아니라 BSGS의 임의 step 요구를 만족하기 위한 **필요 비용**이지만, 실제로 사용되는 step은 `{1..m1−1} ∪ {m1, 2m1, …, (m2−1)m1}` 뿐이다. 사용되지 않는 키가 다수 생성된다(**개선 여지 큼**).

### 2.4 Slot Utilization

- Baseline: 각 청크가 N 슬롯을 사용, `pirBlockSize = 2N`
- bgsg: padding으로 청크의 **`2N` 슬롯 전체를 사용** (값 자체는 duplicated)

→ slot util은 50% → 100%로 증가하지만, 동일 데이터의 중복이므로 **유효 정보 밀도는 동일**. batch_size 계산식 `slot_count / pirBlockSize`은 baseline과 동일하므로 패킹 효율 회귀 없음.

---

## 3. 정확성 모델 — bgsg가 baseline과 동등한 출력을 내는 조건

### 3.1 수학적 등가성

baseline의 출력:

```
y[s] = Σ_{d=0}^{N-1} (rot(x, d)[s]) · diag_d[s]
     = Σ_d x[s+d] · M_total[s][s+d mod N]
```

bgsg는 `d = j·m1 + i` 로 분해하여:

```
y[s] = Σ_j rot( Σ_i rot(x, i)[s] · padded_diag_{i,j}[s] , j·m1 )
```

여기서 `padded_diag_{i,j}[s]` 는 line 354의 `orig_row = (s − j·m1) mod N` 인덱싱으로 인해 **rotation by `j·m1` 후 원래 `diag_{j·m1+i}` 와 동일**해야 한다. 이 등가성이 성립하는 조건:

- **(C1) 회전 자체가 cyclic over `slot_count`** — SEAL CKKS의 rotation은 이를 만족.
- **(C2) `j·m1 < pirInnerDim = N`** — m2 = ⌈N/m1⌉ 이므로 `(m2−1)·m1 ≤ N−1` ⇒ 항상 성립. ✓
- **(C3) Duplicate padding이 슬롯 `[N, 2N)` 까지 동일 데이터로 채워져 있어야** rotation이 청크 경계를 넘지 않음. 코드는 `row < nGlobal*2` 로 정확히 이를 채움. ✓
- **(C4) `j·m1` 의 rotation이 다음 청크의 데이터를 끌어오지 않아야** — `pirBlockSize = 2N` 이고 `j·m1 < N` 이므로 다음 청크는 슬롯 `[2N, 4N)` 에서 시작. 청크 c의 데이터는 [2cN, 2cN+2N), rotation 후 chunk c의 유효 영역은 [2cN+j·m1, 2cN+j·m1+N). 이는 다음 청크와 겹치지 않음. ✓
- **(C5) Baby step 0(= 무회전)이 곧 입력 ciphertext** — 코드는 `baby_steps[0] = cipherChunks[k]` 로 정확. ✓

### 3.2 CKKS 노이즈 관점에서의 등가성

CKKS는 근사 동형이므로 "수학적 등가"는 "복호 후 동일 평문"을 의미하지 않는다. bgsg와 baseline의 노이즈 누적은 다음 차이를 가진다:

- **(N1) Rotation 노이즈 누적 횟수:** baseline은 매 d마다 rotation. bgsg는 baby step `m1−1` 회 + giant step `m2−1` 회. **개별 rotation의 노이즈는 거의 동일**하므로 총 rotation 노이즈는 줄어든다.
- **(N2) 누적 add 순서:** giant-step 내부에서 add 누적 후 rotation을 한 번 더 거치므로 noise term의 분포가 다르다. 그러나 무시할 수준.
- **(N3) Scale 강제 일치(`multiplied.scale() = scale`):** 양쪽 동일하게 수행. 차이 없음.
- **(N4) Mod-switch 타이밍:** giant_acc 누적 시 mod_switch가 추가로 호출됨. 같은 level에서 호출되면 no-op이므로 실측 정확도 차이는 미미.

→ **이론적으로 bgsg는 baseline 대비 노이즈 측면에서 동등 또는 약간 우수**해야 한다. 만약 실측에서 bgsg가 더 나쁜 정확도를 보인다면 그것은 **구현 버그**의 신호다.

### 3.3 Phase 4 보조 변경(라운딩·결정론적 정렬)의 의미

코드는 bgsg와 함께 Phase 4에 라운딩 양자화(`round(val·1e5)/1e5`)와 결정론적 정렬(lex tie-break)을 도입했다. 이는 **bgsg의 정확도를 위해 필요한 것이 아니라**, 본래 CKKS PageRank 노이즈가 만들어 내는 top-K 비결정성을 잡기 위한 **독립적 개선**이다. 분리해서 평가해야 한다.

---

## 4. 엣지 케이스 카탈로그

| ID | 케이스 | 현재 거동 | 위험도 |
|---|---|---|---|
| **E1** | `m1 = 1` (Auto-Tune이 극단 선택) | baby_steps 사전계산 없음, 사실상 baseline로 회귀하면서 padding 오버헤드만 발생 | 낮음 (성능 손실) |
| **E2** | `m1 = N` (반대 극단) | baby_steps에 N개 ciphertext 저장 → 메모리 폭발 | 중간 (OOM 가능) |
| **E3** | `m2 = 1` | giant rotation 0회, 모든 d가 i = d, j = 0 → padding region이 사용되지 않음 | 낮음 |
| **E4** | OMP 스레드 간 `galois_keys` 동시 read | SEAL `GaloisKeys` 의 thread safety 미문서 | **높음**: race condition 가능성, 검증 필요 |
| **E5** | OMP 스레드별 `Evaluator` 생성 | `Evaluator(*context)` 가 context의 read-only 상태에 의존. context는 `shared_ptr` 로 공유됨 | 낮음 (SEAL 보장) |
| **E6** | Auto-Tune 측정 noise (line 562-566의 단일 샘플) | wall-clock jitter로 weight가 1.0~5.0 사이에서 크게 흔들림 | **중간**: 재현성 저하 |
| **E7** | Auto-Tune의 더미 측정이 step=16 하드코딩 (line 564) | 실제 giant step `m1` 과 다른 step을 측정 → cost model 부정확 | **중간**: 잘못된 (m1, m2) 선택 |
| **E8** | Phase 5 Auto-Tune은 weight 적용, Phase 3는 weight=1.0 고정 (line 182) | 같은 시스템에서 다른 cost model | **중간**: 일관성 결함 |
| **E9** | `nGlobal` 이 매우 큼 (e.g., 4096) → galois key `O(N)` | 키 생성 시간이 초기화의 대부분을 차지 | **높음**: 확장성 |
| **E10** | 빈 chunk (num_targets % batch_size = 0 인데 num_chunks 계산이 어긋남) | `ceil` 로 보호되지만 last chunk가 비었을 때 빈 ciphertext 처리 미정의 | 낮음 |
| **E11** | `D < m1 + m2 − 2` (대각선이 매우 sparse) | bgsg의 rotation이 plain-mult보다 많음, 역효과 | 낮음 (sparse 브랜치와 통합 시 핵심) |
| **E12** | duplicate padding을 sparse 브랜치와 합칠 때 sparse 영점 위치가 padding region에 잘못 매핑 | 미래 위험 (B 단계) | **중간**: 통합 시 고려 |
| **E13** | `j·m1` rotation 시 마지막 청크가 슬롯 끝을 넘어서 zero-pad 영역으로 진입 | rotation은 cyclic이므로 vector head로 wrap-around. 첫 청크 데이터가 마지막 청크에 노출됨 | **중간**: chunk-isolation 가정 깨질 가능성 |
| **E14** | CKKS scale 누적 drift (`scale()=scale` 강제 후 add) | 정확도 미세 손실. baseline과 동일하므로 신규 위험 없음 | 낮음 |
| **E15** | `real_weight` 클램프 `[1.0, 5.0]` (line 570-571) | 임의 상수. 시스템에 따라 cap이 부적절 | 낮음 (실측 영향 미미) |
| **E16** | `dummy_cipher` 가 fresh ciphertext (level L). 실제 BSGS rotation은 mid-level에서 일어나서 비용이 다름 | weight 측정이 비현실적 | **중간**: cost model 부정확 |

---

## 5. 강화안 — `feat/bgsg-experiment` 위에 직접 얹을 변경 제안

다섯 제안 각각에 대해 (가설, 변경 위치, 측정 메트릭, 위험)을 명시한다.

### 5.1 [P1] Galois Key Slimming

- **가설:** 실제 사용되는 step은 `{1..m1−1} ∪ {m1, 2m1, …, (m2−1)m1}` 뿐. 이 step set만 생성하면 galois_keys 메모리·생성시간이 `O(N) → O(m1+m2) ≈ O(√N)` 로 감소한다.
- **변경 위치:** `InitializeFHE()` line 244-246. `nGlobal`을 위한 set과 `nSub`을 위한 set의 합집합을 사전 계산.
- **선결 조건:** `FindOptimalAsymmetricBSGS(nGlobal, …)`를 `InitializeFHE` 호출 전에 평가할 수 있어야 한다. 현재 main 단의 호출 흐름은 `InitializeFHE → FindOptimal → PreparePublicData` 이므로 순서 재배치 필요. Phase 5의 (m1, m2) 는 런타임 measurement 후에 결정되므로 두 단계 키 생성이 필요할 수 있음 — 또는 Phase 5에서만 추가 키를 lazy하게 생성.
- **측정 메트릭:** `galois_keys` 직렬화 사이즈 (MB), `create_galois_keys` wall-clock, peak RSS.
- **위험:** 사용 step이 누락되면 SEAL이 런타임 throw. 미리 union 계산을 정확히 해야 함.

### 5.2 [P2] Auto-Tune Robustness — 워밍업·다중 샘플·정확한 step 측정

- **가설:** 현재 weight 측정(라인 562-566)은 단일 샘플 + step=16 하드코딩이라 분산이 크고 편향됨. 다음을 적용한다:
  1. 워밍업 3회(측정 제외)
  2. baby/giant 각각 5회 측정 후 **중앙값** 사용
  3. giant 측정 step = `current_m1` (Phase 3에서 결정된 값) 또는 `√nSub` 의 정수 반올림으로 선택
  4. 측정 ciphertext의 level을 BSGS 실제 사용 level과 일치시킴 (한 번 rescale 후 측정)
- **변경 위치:** Phase 5 line 549-575를 `MeasureRotationWeight(...)` 헬퍼로 추출.
- **측정 메트릭:** 5회 실행 간 `real_weight` 의 표준편차, 동일 입력에서의 (m1, m2) 결정 일관성.
- **위험:** 워밍업이 노이즈 예산을 미세하게 소모. ciphertext 복제로 회피.

### 5.3 [P3] 통합 Cost Model — Phase 3에도 measurement 적용

- **가설:** Phase 3가 `weight=1.0` 고정인 것은 임시 결정. P2의 weight를 InitializeFHE 직후 한 번 측정해서 **Phase 3와 Phase 5 모두**가 동일한 measurement를 사용하도록 한다.
- **변경 위치:** `RunPipeline()` line 175(InitializeFHE 직후) → measure → Phase 3 호출에 weight 주입.
- **부수 효과:** Phase 3 (m1, m2) 가 실제 시스템에 맞춰 조정됨. 측정 cost가 한 번 추가.
- **측정 메트릭:** Phase 3 wall-clock의 weight 민감도.

### 5.4 [P4] Cost Function 일반화 — Plain-mult 비용 포함

- **가설:** 현재 cost = `m1 + w·m2` 는 plain-mult를 무시한다. 실제로는 `m1·T_rot + (m2−1)·T_giant_rot + D·T_mult` (D = 비영 대각선 수). D가 작을수록 (sparse한 그래프) m1+m2 최소화가 wall-clock 최소화와 불일치할 수 있다.
- **변경 위치:** `FindOptimalAsymmetricBSGS` 시그니처에 `D, T_mult/T_rot` 추가. 호출자가 D를 계산해서 전달.
- **선결 조건:** Phase 3 호출 시점에 D를 알아야 함. PreparePublicData에서 estimated D를 반환하거나, 두 단계 호출(추정 → 정밀)로 분리.
- **측정 메트릭:** sparse 그래프(density < 0.3)에서의 m1, m2 선택과 wall-clock.
- **메모:** B(통합) 단계에서 sparse 브랜치와 합칠 때 결정적으로 중요.

### 5.5 [P5] Thread-safety 명시화 — `GaloisKeys` 읽기 동시성 검증

- **가설:** OMP 스레드들이 `galois_keys` 를 동시에 읽는다. SEAL `GaloisKeys` 는 내부적으로 KSwitchKeys 컨테이너이며, **읽기 전용 접근은 thread-safe**여야 한다(공식 문서엔 명시 없음). 우리는 (i) 코드 주석으로 명시, (ii) ThreadSanitizer로 검증, (iii) 위반 시 thread-local clone 패턴 도입.
- **변경 위치:** Phase 3, Phase 5의 OMP 블록 위에 명시적 주석 + CI에 TSan 빌드 추가.
- **측정 메트릭:** TSan 출력, 4·8·16 스레드 결과 일관성.
- **위험:** TSan false positive 가능. SEAL upstream issue 참조 필요.

### 5.6 [P6 — 선택] Baby Step Re-use Across Iterations (Phase 5)

- **가설:** Phase 5는 `ITERATIONS = 10` 의 power-iteration. 매 iteration에서 새로 암호화된 `cipherV` 에 대해 baby_steps를 다시 계산. 만약 server가 `cipherV`의 noise budget을 관리할 수 있다면 iteration 사이 baby_steps를 재사용 가능. 단, 현재 구현은 매 iteration마다 decrypt → re-encrypt 하므로 baby_steps 재사용 불가.
- **변경:** 노이즈 예산이 충분하다면 decrypt 생략 후 baby_steps 재사용. 그러나 이는 본 spec의 범위(BSGS 보강)를 넘어 **프로토콜 변경**에 해당하므로 별도 spec 권장.

---

## 6. 측정 계획 (사전 정의, 사후 cherry-pick 방지)

### 6.1 비교군

1. `main` (베이스라인)
2. `feat/bgsg-experiment` (현재 head)
3. `feat/bgsg-experiment` + P1
4. + P1 + P2
5. + P1 + P2 + P3
6. + P1 + P2 + P3 + P4 (cost 일반화)
7. + P5 (thread-safety는 정성적 검증이므로 별도 분기)

### 6.2 Sweep 파라미터

- `nGlobal ∈ {256, 512, 1024, 2048}`
- `nSub ∈ {64, 128, 256}`
- `num_targets ∈ {1, 4, 16, 64}`
- OMP 스레드: 1, 2, 4, 8

### 6.3 메트릭

| 카테고리 | 메트릭 | 단위 |
|---|---|---|
| 시간 | Phase 1, 3, 5 wall-clock; InitializeFHE wall-clock | sec |
| 시간 | Rotation 단위 시간 (warmup 후 중앙값) | ms |
| 메모리 | `galois_keys` 직렬화 크기 | MB |
| 메모리 | Peak RSS (전체 프로세스) | MB |
| 정확도 | `\|fheScore − groundTruthScore\| ` per target | 무차원 |
| 정확도 | Top-K 일치율 (Phase 4 출력 vs 평문 PageRank) | 0~1 |
| 결정성 | 동일 seed 10회 실행에서 출력 분산 | 무차원 |

### 6.4 통계 프로토콜

- 각 (구성, 파라미터) 조합당 **N = 5회** 실행
- 시간 메트릭은 중앙값 + IQR 보고 (평균·표준편차 X — wall-clock은 long-tail)
- 정확도는 평균 + max
- Sanity check: P1만 적용은 정확도에 영향 없어야 함; 차이가 있다면 구현 버그.

### 6.5 환경 고정

- CPU governor `performance`
- OMP_PROC_BIND=close, OMP_PLACES=cores
- SEAL build flags, hugepages 설정 명시
- 동일 머신/동일 빌드로 1회 sweep 완료

---

## 7. 정확성 회귀 테스트 (필수)

각 강화안 적용 후 다음이 보장되어야 함:

1. **R1:** baseline과 bgsg가 동일 입력에서 **Phase 3 출력 ciphertext를 복호한 평문이 ε 내 일치** (`max|y_baseline − y_bgsg| < 10^{−4}` 권장)
2. **R2:** `m1=1, m2=N` 일 때 baseline와 bit-for-bit 동등 출력 (사실상 같은 코드 경로)
3. **R3:** Auto-tune off/on 결과의 Phase 6 verdict (APPROVED/REJECTED) 일치
4. **R4:** OMP 1-스레드와 4-스레드 결과의 비트 동등성 (rotation 순서 무관)

---

## 8. 개방 문제 (Future Work)

- **O1:** `D` 의존성을 cost model에 포함했을 때, B 단계의 sparse 브랜치와 결합 시 m1, m2 선택이 main 대비 어떻게 달라지는가?
- **O2:** CKKS slot rotation 비용이 모듈러스 chain level에 따라 어떻게 변하는가? Auto-tune이 level을 고려해야 하는가?
- **O3:** baby_steps 사전계산을 lazy하게 (`item.i` 가 처음 등장할 때만) 평가하면 메모리·시간 모두 절감 가능. trade-off는?
- **O4:** `GaloisKeys` thread-safety가 SEAL upstream에서 명시되지 않은 상태. 우리가 issue를 열어 명확화를 요청해야 하는가?
- **O5:** Phase 5의 decrypt→re-encrypt 루프(line 622-625) 는 실제 PIR 프로토콜이 아니다. 동형 정규화(homomorphic normalization)로 대체할 수 있는가?

---

## 9. 비-목표 (Non-Goals)

- 본 spec은 **Phase 1 평문 전처리 비용**(O(N³))을 다루지 않음 → A2의 sparse 브랜치 영역
- 본 spec은 **CKKS scheme 변경**(BFV로 전환, bootstrapping 등)을 고려하지 않음
- 본 spec은 **PIR 프로토콜 변경**(클라이언트-서버 round 수)을 고려하지 않음

---

## 10. 의존성과 순서

권장 적용 순서:

1. **P5** (thread-safety 검증) — 다른 강화안에 독립적, 먼저 수행해 신뢰 확보
2. **P2** (auto-tune robustness) — P3, P4의 기반
3. **P3** (통합 cost model) — P2 위에 빌드
4. **P1** (galois key slimming) — P2, P3가 정한 (m1, m2)를 사용
5. **P4** (cost function 일반화) — B 단계 결합 직전에 활성화

P6는 별도 spec.

---

## 11. 본 spec이 학술적으로 기여하는 바

- **(a)** CKKS PIR의 *비용 모델*을 rotation/multiplication/level의 분리된 항으로 명시 — 일반 BSGS 문헌은 `m1 + m2` 만 다루나, 실제 wall-clock은 plain-mult, mod-switch 비용도 포함됨을 지적
- **(b)** *시스템 측정 기반 cost weight* 의 sampling 분산 문제를 형식화 (P2)
- **(c)** *Galois key 비용* 을 BSGS step set에 따라 정확히 정량화 — 기존 문헌은 정성 언급에 그침
- **(d)** *복호 후 정렬 노이즈* (Phase 4)와 *PIR 추출 노이즈* (Phase 3)를 분리해야 함을 지적 — bgsg 브랜치의 보조 변경이 실제로 잡고 있는 문제의 정체

---

## 부록 A — 변경 코드 참조 색인

| 위치 | 라인 | 항목 |
|---|---|---|
| `CipherRank.cpp` | 49-58 | `BsgsDiag` |
| | 63-69 | `BSGSParams` |
| | 81-105 | `FindOptimalAsymmetricBSGS` |
| | 182 | Phase 3 호출 시 weight=1.0 |
| | 244-246 | Galois key step 명시 (`1..nGlobal`) |
| | 266-369 | `PreparePublicData` (padding line 353) |
| | 403-460 | `ExtractBlindSubgraph` (OMP line 407, baby loop line 413, giant loop line 420) |
| | 486-491 | Phase 4 라운딩 + 결정론 정렬 |
| | 549-575 | Phase 5 weight measurement |
| | 577-579 | Phase 5 auto-tune 호출 |
| | 588-611 | Phase 5 BSGS diagonal 생성 |

