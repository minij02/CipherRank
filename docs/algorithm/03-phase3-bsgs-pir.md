# 3. 동형 PIR — Halevi-Shoup 분해와 비대칭 BSGS

Phase 3 의 임무는 평가 대상의 인덱스 정체를 서버에 노출하지 않은 채, 행렬 M_total 의 그 인덱스 *열* 을 동형으로 추출하는 것이다. 평문 세계에서 이는 단순한 열 조회로 환원되지만, CKKS 위에서는 "행렬 × one-hot 벡터" 의 동형 곱으로 풀어야 한다. 본 장은 그 곱을 회전 · 평문 곱 · 덧셈만의 조합으로 표현하는 Halevi-Shoup 의 대각선 분해를 §3.3 에서 소개하고, 회전 횟수를 O(N) 에서 O(√N) 으로 축소하는 비대칭 Baby-Step Giant-Step (BSGS) 알고리즘을 §3.4 에서 다룬다. 슬롯 패킹의 청크 경계 안전성은 §3.5 에서 형식적으로 진술하며, 부록 §3.A 는 §1.6 의 N = 4 예제 위에서 BSGS 의 결과 슬롯이 정의식과 일치함을 손 계산으로 검증한다.

## 3.1 클라이언트 측 one-hot 인코딩

클라이언트는 평가 대상 K 명을 청크 단위로 묶어 SIMD 암호화한다 (`CipherRank.cpp:519–537`).

```cpp
for (int k = 0; k < num_chunks; k++) {
    vector<double> v_target(slot_count, 0.0);
    for (int c = 0; c < current_batch; c++) {
        int idx = targetGlobalIndices[start_idx + c];
        v_target[c * pirBlockSize + idx]               = 1.0;
        v_target[c * pirBlockSize + pirInnerDim + idx] = 1.0;
    }
    Plaintext pt; encoder->encode(v_target, scale, pt);
    cipherChunks.push_back(encryptor->encrypt(pt, ...));
}
```

한 청크는 슬롯 공간의 [c · 2N, (c + 1) · 2N) 영역을 차지하며, 그 안에 `batch_size = slot_count / 2N` 명의 평가 대상이 담긴다. 각 평가 대상에 대해 idx 슬롯과 그 +N 슬롯에 동시에 1 을 적는 *중복 인코딩* 이 본 인코딩의 핵심이다. 이 중복이 §3.5 의 청크 경계 안전성을 보장한다.

## 3.2 평문 세계의 행렬-벡터 곱

서버가 보유한 BsgsDiag 리스트는 행렬 M = M_total = M_pub + β₂ · M_pub² 의 d 번째 대각선 정보를 슬롯에 인코딩한 것이다. 즉 모든 d ∈ [0, N) 에 대해

$$\mathrm{diag}_{d}[\mathrm{row}] = M[\mathrm{row}][(\mathrm{row} + d) \bmod N]$$

가 성립한다. 일반적인 행렬-벡터 곱 y = M · x 는 대각선 합산으로 다음과 같이 표현된다.

$$y[\mathrm{row}] = \sum_{d=0}^{N-1} \mathrm{rot}(x, d)[\mathrm{row}] \cdot \mathrm{diag}_{d}[\mathrm{row}] = \sum_{d=0}^{N-1} x[(\mathrm{row} + d) \bmod N] \cdot M[\mathrm{row}][(\mathrm{row} + d) \bmod N] \quad \cdots (3.1)$$

x 가 위치 p 에 1 을 갖는 one-hot 일 경우 식 (3.1) 은 y[row] = M[row][p] 로 환원된다. 결과 ciphertext 의 슬롯 row 에는 "평가 대상이 p 일 때 p 가 row 에게 부여하는 신뢰의 1+2-홉 누적값" 이 적힌다.

이 합을 동형으로 평가한다는 것은 다음 세 연산을 ciphertext 영역에서 수행한다는 의미이다.

(i) x 의 회전: CKKS rotation 1 회는 Galois automorphism 1 회와 key-switching 1 회로 구성되며, BSGS 의 전체 비용 중 가장 큰 비중을 차지한다.

(ii) 회전된 ciphertext 와 평문 대각선의 곱: `multiply_plain` 으로 처리되며, 회전 비용에 비해 무시할 만큼 저렴하다.

(iii) 누적 합산: ciphertext 끼리의 `add_inplace`. 거의 비용이 없다.

baseline 구현 (`main` 브랜치) 은 식 (3.1) 의 합을 N 회의 반복으로 그대로 평가한다. 즉 d 마다 회전 1 회, 곱셈 1 회, 덧셈 1 회가 발생하며 N = 1024 의 경우 총 1024 회의 key-switching 이 요구된다.

## 3.3 Halevi-Shoup 의 대각선 분해

식 (3.1) 의 d 를 `d = j · m₁ + i` (단, 0 ≤ i < m₁, 0 ≤ j < m₂, m₁ · m₂ ≥ N) 로 분해하면 합을 이중 합으로 재구성할 수 있다.

$$y[\mathrm{row}] = \sum_{j=0}^{m_2-1} \mathrm{rot}\!\left( \sum_{i=0}^{m_1-1} \mathrm{rot}(x, i) \cdot \widetilde{\mathrm{diag}}_{i,j} \,,\, j \cdot m_1 \right)[\mathrm{row}] \quad \cdots (3.2)$$

여기서 $\widetilde{\mathrm{diag}}_{i,j}$ 는 `diag_{j·m₁ + i}` 를 역방향으로 j · m₁ 만큼 사전 회전한 평문이다. 즉 평문 인코딩 단계에서 row 의 슬롯 위치를 `(row + j · m₁) mod N` 으로 옮겨 둔다. §2.6 의 `slot_idx = (row + j · m₁) mod N` 가 정확히 이 인덱싱이다.

식 (3.2) 의 핵심은 회전이 두 종류의 위치에서만 발생한다는 점이다.

**Baby steps.** `rot(x, 0), rot(x, 1), …, rot(x, m₁ − 1)` 을 입력 ciphertext 에 대해 사전에 계산하여 thread-local 저장한다. m₁ − 1 회의 회전이 요구된다.

**Giant steps.** 안쪽 합 (i 축의 합) 결과를 j · m₁ 만큼 회전한다. j = 0 은 회전이 불필요하므로 m₂ − 1 회의 회전이 요구된다.

따라서 BSGS 의 총 회전 횟수는 m₁ + m₂ − 2 이며, 제약 m₁ · m₂ ≥ N 하에서 m₁ = m₂ = √N 일 때 최소가 된다. 그 최소값은 약 2√N − 2 이며, N = 1024 의 경우 baseline 의 1024 회 대비 약 30 회로 35 배 감축된다.

평문 곱셈과 덧셈의 횟수는 baseline 과 BSGS 사이에 변동이 없다 (둘 다 D 회, D 는 비공실 대각선의 수). 감축되는 것은 *회전* 뿐이다.

## 3.4 비대칭 BSGS 와 비용 모델

baby step 의 회전과 giant step 의 회전은 모두 key-switching 1 회를 포함하지만, 대상 ciphertext 의 modulus chain 레벨이 다르다. baby step 은 입력 ciphertext (레벨 L) 위에서, giant step 은 한 번 rescale 된 누적 결과 (레벨 L − 1) 위에서 일어난다. CKKS rotation 의 시간 비용은 modulus 의 RNS prime 수에 비례하므로 두 회전의 절대 비용은 동일하지 않다.

본 시스템의 비용 함수는 baby step 1 회의 비용을 단위 1 로 두고, giant step 의 상대 비용을 `giant_weight` 로 모델링한다 (`CipherRank.cpp:96–123`).

```cpp
BSGSParams FindOptimalAsymmetricBSGS(int N, double giant_weight) {
    int best_m1 = 1, best_m2 = N;
    double min_cost = 1e9;
    for (int m1 = 1; m1 <= N; m1++) {
        int m2 = (N + m1 - 1) / m1;
        double cost = m1 + giant_weight * m2;
        if (cost < min_cost) { min_cost = cost; best_m1 = m1; best_m2 = m2; }
    }
    return {best_m1, best_m2};
}
```

`giant_weight = 1.0` 의 경우 최적해는 대칭 m₁ = m₂ = √N 으로 수렴한다. 본 시스템은 측정의 단순화를 위해 `giant_weight = 1.0` 을 고정값으로 사용하며, 그 결과 N = 1024 의 경우 m₁ = m₂ = 32, N = 4096 의 경우 m₁ = m₂ = 64 가 산출된다.

설계 명세 (`A1 spec` 의 P2) 는 시스템 시작 시 더미 ciphertext 로 baby/giant 회전의 실제 시간을 측정하여 `giant_weight` 를 자동 조정하는 튜너를 제안한다. 그러나 이 weight 의 변화가 Galois key step 집합의 변화를 유발하는 의존 사이클이 존재하므로, 통합 단계의 안정성을 우선하여 현재는 측정값을 기록하되 사용하지는 않는다. 후속 작업으로의 분리는 §6 의 후속 항목에서 다룬다.

## 3.5 슬롯 패킹과 청크 경계 안전성

CKKS ciphertext 한 개가 보유하는 슬롯 수는 `slot_count = poly_modulus_degree / 2` 이다. 한 청크는 그 중 `pirBlockSize = 2N` 슬롯을 차지하며, 청크 내부에서 앞 N 슬롯은 one-hot 유효 영역, 뒤 N 슬롯은 동일 one-hot 의 복제 영역이다.

복제 인코딩이 요구되는 이유는 다음의 보조정리로 진술된다.

**보조정리 3.1 (C4, 동형 패턴 청크 평행 이동 불변성).** 모든 청크가 동일한 슬롯 패턴을 보유하고, 청크 안의 [c · 2N, c · 2N + N) 영역과 [c · 2N + N, c · 2N + 2N) 영역이 동일한 평문을 보유한다고 하자. 이 가정 하에서, 임의의 회전 step k 에 대해 회전된 결과의 슬롯 c · 2N + s 의 값은 원래 청크의 슬롯 c · 2N + (s − k mod N) 의 값과 같다.

**보조정리 3.2 (C8, 청크 경계 회전 안전).** 보조정리 3.1 의 가정 하에서, BSGS 의 giant step 회전 `j · m₁` 이 청크 영역 [c · 2N, (c + 1) · 2N) 안에서 닫혀 있는 한 옆 청크로의 누설은 일어나지 않는다.

증명의 완전한 형태는 통합 명세 (`docs/superpowers/specs/2026-06-18-bgsg-strengthening-design.md`, §3.1) 에 분해되어 있으며, 본 보고서에서는 그 결론만 사용한다.

조건 `j · m₁ < N` 은 m₂ = ⌈N / m₁⌉ 의 정의에서 `(m₂ − 1) · m₁ < N` 으로 자동 보장된다. 따라서 §2.6 의 Q7 패딩이 정확히 보조정리 3.1 의 가정 (청크 안 두 영역의 동일성) 을 만족시키는 인코딩 처리이며, 이로써 BSGS 가 다중 청크 환경에서도 안전하게 작동한다.

A2 단독 구현 (가지치기는 도입되었으나 BSGS 가 도입되기 전) 에서는 청크 안의 뒤 N 슬롯이 0 으로 채워져 있어 보조정리 3.1 의 가정이 만족되지 않는다. 이 상태에서 BSGS 를 도입하면 즉시 누설이 발생하므로, 통합 단계에서의 Q7 패딩 도입은 알고리즘 수준의 필수 조건이다.

## 3.6 OpenMP 청크 분배와 thread-local SEAL 객체

청크 K 개의 처리는 동일한 BsgsDiag 리스트와 Galois key 를 read-only 로 공유하므로, 서로 완전히 독립적이다. 본 시스템은 청크 루프를 OpenMP 로 분배한다 (`CipherRank.cpp:551–602`).

```cpp
#pragma omp parallel for
for (int k = 0; k < num_chunks; k++) {
    Evaluator thr_eval(*context);   // thread-local
    vector<Ciphertext> baby_steps(m1);
    // ... §3.3 의 baby step 사전 계산과 giant step 누적
}
```

`Evaluator` 가 thread-local 인 이유는 SEAL 내부의 `MemoryPoolHandle` 이 thread-safe 하지 않기 때문이다. `context` 와 `galois_keys` 자체는 read-only 이므로 공유 가능하다. Phase 5 의 경우 매 반복에서 재암호화가 발생하므로 `Encryptor` 와 `Decryptor` 도 thread-local 로 유지해야 하며, 이는 통합 명세의 H-2 패치가 적용한 처리이다 (§4.5 참조).

Config B (N = 1024, 청크 5 개, P = 4) 의 Phase 3 wall-clock 은 평균 0.94 초이며, baseline 의 동일 설정에서의 21.5 초 대비 약 22.4 배 단축된다. 이 단축률은 이론치 (회전 수 비율 × OpenMP 분배 비율 ≈ 85 배) 의 약 1/4 수준으로, OMP context switching, thread-local Evaluator 생성 비용, 청크 작업 불균형 등의 요인이 격차의 원인이다.

## 3.7 베이비 스텝 사전 계산의 메모리

baby step 사전 계산은 m₁ 개의 ciphertext 를 thread-local 로 보존한다. 각 ciphertext 의 크기를 약 0.5 MB 로 추산하면, P = 4 · m₁ = 32 의 경우 thread 당 16 MB, 동시 peak 으로는 64 MB 가 요구된다. N = 4096 의 경우 m₁ = 64 이고 ciphertext 크기도 증가하므로 동시 peak 이 수백 MB 단위에 도달할 수 있다.

baby step 의 재사용 가능성은 후속 연구 주제로 남는다. Phase 5 의 10 회 멱법 반복 사이에 동일 baby step 을 재사용할 수 있다면 회전 수가 10 배 감축될 것이나, 그러기 위해 요구되는 CKKS useful depth 가 현재의 modulus 사슬 `{60, 45, 45, 60}` 으로는 확보되지 않는다. 본 시스템의 Phase 5 가 매 반복마다 복호 후 재암호화의 단순화를 도입한 직접적 이유가 여기에 있다 (§4.5).

## 3.8 출력의 형태

Phase 3 의 출력은 K 개의 ciphertext 이다. 각 ciphertext 의 청크 c 영역 [c · 2N, c · 2N + N) 에는, 그 자리의 평가 대상이 다른 N − 1 개 노드 각각에게 받는 1+2-홉 누적 trust 분포가 인코딩되어 있다. 이 ciphertext 들이 Phase 4 의 복호 및 상위 nSub 추출의 입력이 된다.

---

## 부록 3.A — N = 4 예제에 대한 BSGS 곱셈의 슬롯 단위 검증

§2.A 의 끝에서 구성한 네 BsgsDiag 평문을 사용하여, 평가 대상 wallet 30 (globalIdx = 1) 의 one-hot 암호문에 대한 Phase 3 의 출력이 식 (3.1) 의 정의에 부합함을 슬롯 단위로 검증한다.

### 3.A.1 one-hot 의 슬롯 분포

`v_target[c · 2N + idx] = 1.0` 와 `v_target[c · 2N + N + idx] = 1.0` 을 idx = 1, c = 0, N = 4 에 적용하면 길이 8 의 슬롯 벡터는 다음과 같다.

```
x = [0, 1, 0, 0, 0, 1, 0, 0]
     ─── N 영역 ───   ─── 패딩 ───
```

이 벡터를 CKKS encode 와 encrypt 를 거쳐 `cipherChunks[0]` 으로 변환한다.

### 3.A.2 베이비 스텝

m₁ = 2 이므로 두 개의 baby step 이 사전 계산된다. SEAL 의 `rotate_vector(x, 1)` 은 slot k 의 값을 slot k − 1 로 가져오는 왼쪽 시프트이므로, 평문 세계의 슬롯 분포로 환산하면 다음과 같다.

- `baby_steps[0]` : `[0, 1, 0, 0, 0, 1, 0, 0]`
- `baby_steps[1]` : `[1, 0, 0, 0, 1, 0, 0, 0]`

### 3.A.3 j = 0 의 giant 누적

j = 0 의 BsgsDiag 는 (i = 0, d = 0) 과 (i = 1, d = 1) 의 두 항이다.

(i = 0): `baby_steps[0]` 과 plain_d0 = [3.6, 3.6, 0, 0, 3.6, 3.6, 0, 0] 의 슬롯별 곱은

$$[0, 1, 0, 0, 0, 1, 0, 0] \cdot [3.6, 3.6, 0, 0, 3.6, 3.6, 0, 0] = [0, 3.6, 0, 0, 0, 3.6, 0, 0].$$

(i = 1): `baby_steps[1]` 과 plain_d1 = [5.8, 5.0, 3.6, 1.8, 5.8, 5.0, 3.6, 1.8] 의 곱은

$$[1, 0, 0, 0, 1, 0, 0, 0] \cdot [5.8, 5.0, 3.6, 1.8, 5.8, 5.0, 3.6, 1.8] = [5.8, 0, 0, 0, 5.8, 0, 0, 0].$$

두 결과의 합 (즉 giant_acc) 은 `[5.8, 3.6, 0, 0, 5.8, 3.6, 0, 0]` 이다. j = 0 의 경우 추가 회전이 발생하지 않는다.

### 3.A.4 j = 1 의 giant 누적과 회전

j = 1 의 BsgsDiag 는 (i = 0, d = 2) 와 (i = 1, d = 3) 의 두 항이다.

(i = 0): `baby_steps[0]` × plain_d2 = `[0, 2.0, 0, 0, 0, 2.0, 0, 0]`.

(i = 1): `baby_steps[1]` × plain_d3 = `[4.8, 0, 0, 0, 4.8, 0, 0, 0]`.

두 항의 합은 `[4.8, 2.0, 0, 0, 4.8, 2.0, 0, 0]` 이다. j = 1 에 대해 `j · m₁ = 2` 만큼의 왼쪽 회전을 적용하면 slot k 의 값이 slot k − 2 (mod 8) 로 이동하므로, 회전 후의 슬롯 분포는

`[0, 0, 4.8, 2.0, 0, 0, 4.8, 2.0]`

이다.

### 3.A.5 최종 합과 정의식과의 비교

j = 0 의 결과와 j = 1 의 (회전된) 결과를 합산한 cipherNeighbors 는 다음과 같다.

$$\mathrm{cipherNeighbors} = [5.8, 3.6, 0, 0, 5.8, 3.6, 0, 0] + [0, 0, 4.8, 2.0, 0, 0, 4.8, 2.0] = [5.8, 3.6, 4.8, 2.0, 5.8, 3.6, 4.8, 2.0].$$

앞 4 슬롯 `[5.8, 3.6, 4.8, 2.0]` 을 식 (3.1) 의 정의 (one-hot p = 1) 와 비교한다.

| row | y[row] = M_total[row][1] (정의) | 슬롯 (계산) | 일치 |
|---:|---:|---:|:---:|
| 0 | 5.8 | 5.8 | ✓ |
| 1 | 3.6 | 3.6 | ✓ |
| 2 | 4.8 | 4.8 | ✓ |
| 3 | 2.0 | 2.0 | ✓ |

모든 row 에 대해 정의식과의 일치가 확인된다. 뒤 4 슬롯에는 동일한 결과가 한 번 더 복제되어 나타나는데, 이는 보조정리 3.1 의 가정 (Q7 패딩에 의한 청크 내 두 영역 일치) 의 직접적 귀결이다. 단일 청크 시나리오에서는 패딩의 효과가 표면적으로 보이지 않으나, 다중 청크 시나리오에서는 §6.2 의 R6 (multi-chunk equivalence) 검증을 통해 패딩의 안전성이 직접 측정 가능한 형태로 드러난다.

### 3.A.6 다중 청크의 경우

평가 대상이 wallet 30 과 wallet 20 두 명인 경우 slot_count = 16 의 가정 하에 두 개의 청크가 구성된다. 청크 1 (슬롯 8..15) 에는 wallet 20 (globalIdx = 2) 의 one-hot 이 인코딩되며, 그 슬롯 분포는 다음과 같다.

```
x = [0, 1, 0, 0, 0, 1, 0, 0,   0, 0, 1, 0, 0, 0, 1, 0]
     ── 청크 0 (wallet 30) ──   ── 청크 1 (wallet 20) ──
```

§2.6 의 BSGS 인코딩 루프에서 각 BsgsDiag 의 평문 패턴이 `for (size_t c = 0; c < batch_size; c++)` 의 외부 루프를 통해 모든 청크 영역에 동일하게 복제된다. 보조정리 3.1 의 가정이 만족되므로 청크 1 의 결과는 청크 0 의 결과와 동일한 슬롯 패턴을 청크 1 의 영역에 산출한다. 청크 1 의 슬롯 8..11 을 복호하면 wallet 20 에 대한 trust 분포 `[M_total[0][2], M_total[1][2], M_total[2][2], M_total[3][2]] = [6.0, 5.0, 0, 3.0]` 이 추출된다.

Q7 패딩이 부재한 경우 청크 0 의 뒤쪽 4 슬롯의 0 값이 회전을 통해 청크 1 의 영역으로 전파되어 wallet 20 의 결과를 0 방향으로 왜곡한다. 이 시나리오는 통합 명세의 R6 검증에서 점수의 ε-등가성 위반으로 검출된다.
