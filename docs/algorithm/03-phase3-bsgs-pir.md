# 3. Phase 3 — Halevi-Shoup PIR 과 비대칭 BSGS

Phase 3 은 평가 대상의 인덱스를 모른 채 그 인덱스가 가리키는 *열* 을 행렬에서 꺼낸다. 평문 세계에서 이런 연산은 단순한 column lookup 이지만, CKKS 위에선 "행렬 × one-hot 벡터" 의 동형 곱으로 풀어야 한다. 이 문서는 그 곱셈이 어떻게 *대각선 분해* (Halevi & Shoup, 2014) 로 회전·평문 곱·덧셈만으로 표현되는지, 그리고 그 회전 횟수를 baseline 의 O(N) 에서 O(√N) 로 줄이는 비대칭 BSGS 가 어떤 모양인지 보인다.

## 3.1 입력 — one-hot 암호문

클라이언트는 평가 대상 K 개를 청크 단위로 묶어 SIMD 암호화한다 (`CipherRank.cpp:512–530`):

```cpp
for (int k = 0; k < num_chunks; k++) {
    vector<double> v_target(slot_count, 0.0);
    for (int c = 0; c < current_batch; c++) {
        int idx = targetGlobalIndices[start_idx + c];
        v_target[c * pirBlockSize + idx]              = 1.0;
        v_target[c * pirBlockSize + pirInnerDim + idx] = 1.0;     // 중복 패딩 영역
    }
    Plaintext pt; encoder->encode(v_target, scale, pt);
    cipherChunks.push_back(encryptor->encrypt(pt, ...));
}
```

한 청크에는 `batch_size` 명까지 들어간다. nGlobal=1024, poly=8192 면 batch_size = 4096 / 2048 = 2 이므로 한 청크에 두 명, 네 명을 평가한다면 두 청크가 만들어진다. nGlobal=256 이면 batch_size = 8 이고 9 명 이상이어야 청크가 둘로 갈린다.

c 번째 슬롯 묶음 `[c · 2N, c · 2N + N)` 안에서 `idx` 위치만 1.0, 나머지는 0.0 이다. 패딩 영역 `[c · 2N + N, c · 2N + 2N)` 에도 같은 위치에 1.0 을 둔다 — 청크가 BSGS giant step 회전 (`j · m₁`) 후에도 자기 슬롯 영역 안에 머무르게 하는 사전 조치다.

## 3.2 평문 세계에서의 목표

서버는 `M = M_total = M_pub + M_pub²` (β = 1, θ = 0 의 baseline 의미 모델 기준) 의 d-번째 대각선을 캐싱해 둔 상태다. 즉 모든 d ∈ [0, N) 에 대해

```
diag_d[row] = M[row][(row + d) mod N]
```

이 행렬-벡터 곱 `y = M · x` 를 표현하면

```
y[row] = Σ_d (rot(x, d)[row]) · diag_d[row]
       = Σ_d  x[(row + d) mod N] · M[row][(row + d) mod N]
```

이다. `x` 가 `p` 위치에만 1.0 인 one-hot 이면 `y[row] = M[row][p]` 가 된다 — 즉 `p` 열의 weight 가 row 별로 그대로 떨어진다. 결과 ciphertext 의 슬롯 row 에 적힌 값은 "이 ciphertext 의 평가 대상이 p 라면, p 가 row 에게 얼마나 trust 를 주고 있는가" 다.

이 식을 동형으로 푼다는 건 다음 세 가지를 동형으로 한다는 뜻이다.

1. **`x` 의 회전**: CKKS rotation 1 회 = Galois automorphism 1 회 = key-switching 1 회. 가장 비싼 연산이다.
2. **회전된 ciphertext × plain diagonal**: `multiply_plain`. 평문 곱이라 회전보다 훨씬 싸다.
3. **누적 합산**: ciphertext 끼리 `add_inplace`. 거의 공짜.

baseline (`main` 브랜치) 은 그대로 이 합을 N 번 돈다. d 마다 회전 1, 곱셈 1, 덧셈 1. N=1024 면 1024 번의 keyswitching 이다.

## 3.3 대각선 분해 — Halevi-Shoup

A1 과 B 는 d 를 `d = j · m₁ + i` 로 쪼개 위 합을 두 단계 합으로 재구성한다.

```
y[row] = Σ_d rot(x, d)[row] · diag_d[row]
      = Σ_j Σ_i rot(x, j·m₁ + i)[row] · diag_{j·m₁+i}[row]
      = Σ_j rot( Σ_i rot(x, i)[row] · pdiag_{i,j}[row] , j·m₁ )
```

여기서 `pdiag_{i,j}` 는 `diag_{j·m₁ + i}` 를 미리 *역방향으로 j·m₁ 만큼 회전* 시킨 평문이다. 즉 평문 인코딩 단계에서 행 위치를 `(row + j·m₁) mod N` 으로 옮겨 둔다 (2절 2.7 의 `slot_idx = (row + j · m₁) % nGlobal` 가 이 인덱싱이다).

이렇게 분해하면 회전이 두 곳에서만 일어난다.

- **Baby steps**: `rot(x, 0), rot(x, 1), …, rot(x, m₁ - 1)` 을 미리 계산해서 보관. m₁ - 1 번의 회전.
- **Giant steps**: 안쪽 합 (`Σ_i ...`) 의 결과를 `j · m₁` 만큼 회전. j = 0 은 회전 없음. 따라서 m₂ - 1 번의 회전.

회전 총합은 m₁ + m₂ - 2. m₁ · m₂ = N 의 제약 하에서 합이 최소가 되는 지점은 m₁ = m₂ = √N 이고, 그때 회전 총합은 약 `2√N - 2` 다. N = 1024 면 baseline 1024 → BSGS 30. 약 34 배 감축이다.

평문 곱셈과 덧셈은 여전히 D = (비영 대각선 수) 만큼 일어난다. baseline 도 BSGS 도 평문 곱과 덧셈의 횟수는 같다. 줄어드는 건 *회전* 뿐이다.

## 3.4 비대칭 BSGS — m₁ 과 m₂ 가 같지 않아도 되는 이유

baby step 의 회전과 giant step 의 회전의 wall-clock 비용이 다르다는 게 핵심이다. 두 회전 모두 key-switching 1 회씩이지만, *대상 ciphertext 의 modulus chain 레벨* 이 다르다. baby step 은 입력 ciphertext (level L) 위에서, giant step 은 한 번 rescale 된 (level L-1) 누적 결과 위에서 일어난다. CKKS rotation 의 시간은 modulus 의 RNS prime 수에 비례하므로 두 회전의 비용이 같지 않다.

코드의 cost 함수는 다음과 같다 (`CipherRank.cpp:96–123`):

```cpp
BSGSParams FindOptimalAsymmetricBSGS(int N, double giant_weight) {
    int best_m1 = 1, best_m2 = N;
    double min_cost = 1e9;
    for (int m1 = 1; m1 <= N; m1++) {
        int m2 = (N + m1 - 1) / m1;          // m₁·m₂ ≥ N 의 최소
        double cost = m1 + giant_weight * m2;
        if (cost < min_cost) { min_cost = cost; best_m1 = m1; best_m2 = m2; }
    }
    return {best_m1, best_m2};
}
```

`giant_weight` 가 정확히 1.0 이면 baby 와 giant 가 같은 비용이라 보고, 그때의 최적해는 대칭 m₁ = m₂ = √N 이다. `giant_weight` 가 더 크면 (예: 2.0) m₁ 을 키워 giant step 수를 줄이는 게 이득이다. 통합 브랜치는 시간 측정의 단순화를 위해 `giant_weight = 1.0` 으로 고정한다 — 실측에서 N = 1024 → m₁ = m₂ = 32, N = 4096 → m₁ = m₂ = 64 가 나온다.

원래 A1 spec 의 P2 는 startup 시점에 dummy ciphertext 로 baby/giant 회전 시간을 측정해 실제 weight 를 도출하는 자동 튜너를 두지만, 이 weight 에 따라 Galois key step set 도 달라지는 의존 사이클이 있어 (B 통합 단계에서 정리해야 함), 현재는 weight 측정값을 *기록만* 하고 사용하지는 않는다.

## 3.5 슬롯 패킹과 청크 — 왜 [0, 2N) 인가

CKKS 한 ciphertext 가 들고 있는 슬롯이 `slot_count = poly_modulus_degree / 2` 다. poly = 8192 면 4096 슬롯. 한 청크는 그 중 `pirBlockSize = 2N` 슬롯을 차지한다. 청크 안에서 앞 N 슬롯은 one-hot, 뒤 N 슬롯은 *같은 one-hot 의 복제* 다.

이 중복이 왜 필요한지는 다음과 같이 보면 된다. BSGS 의 giant step 은 *입력 회전 결과* 가 아니라 *누적된 안쪽 합* 을 `j · m₁` 만큼 돌린다. CKKS rotation 은 slot_count 의 cyclic shift 이므로, 슬롯 `c · 2N + s` 에 있던 값이 `c · 2N + s + j · m₁` 으로 이동한다 (mod slot_count). 청크 안에서 s + j · m₁ 가 `N` 을 넘어가도 `2N` 안에 머무르면 안전하지만, 만약 청크 영역 `[c · 2N, (c+1) · 2N)` 을 벗어나면 옆 청크의 다른 평가 대상 결과로 누설된다.

A1 의 패딩은 이 문제를 다음과 같이 막는다. 청크 영역의 앞 N 슬롯과 뒤 N 슬롯에 *완전히 같은* one-hot 을 복제해 둔다. 그러면 회전 후 슬롯 분포가 어떻게 바뀌든 청크 영역 내부에서는 항상 의도된 값이 있다 (즉 `pdiag` 의 row 와 곱해질 값이 정확히 그 row 에 정렬된 one-hot 비트다). 정확한 증명은 통합 spec sec 3.1 의 C4 lemma ("Homomorphic Pattern Invariance under Chunk-Translation") 에 분해되어 있다.

`j · m₁ < N` (= A1 C2) 가 충족되는 한 회전이 청크 경계를 넘는 일은 없다. `m₂ = ⌈N / m₁⌉` 으로 잡혀 있으니 `(m₂ - 1) · m₁ < N` 이 항상 성립한다.

A2 만으로는 한 청크의 앞 N 슬롯에만 값을 적었고 (`CipherRank.cpp:303–307` of sparse 브랜치), BSGS 가 도입되는 순간 청크 경계로의 누설이 가능해진다. 통합 단계의 Q7 는 sparseDiag 의 인코딩 루프에서 같은 값을 `slot_idx` 와 `slot_idx + N` 두 곳에 모두 기록하는 한 줄로 해결된다 (2절 2.7).

## 3.6 OpenMP 청크 분배와 thread-local SEAL 객체

청크 K 개의 처리는 서로 완전히 독립이다 — 같은 BsgsDiag 리스트와 같은 Galois key 를 read-only 로 쓸 뿐이다. A1 은 청크 루프를 `#pragma omp parallel for` 로 둘러싼다 (`CipherRank.cpp:558`):

```cpp
#pragma omp parallel for
for (int k = 0; k < num_chunks; k++) {
    Evaluator thr_eval(*context);                    // thread-local
    // ... baby_steps[m₁] 사전 계산
    // ... giant 누적
}
```

`Evaluator` 가 thread-local 인 이유는 SEAL 내부의 `MemoryPoolHandle` 이 thread-safe 하지 않기 때문이다. 같은 `context` 와 `galois_keys` 는 read-only 로 공유해도 안전하다. 다만 Phase 5 는 매 iteration 에서 *재암호* 가 발생하므로 `Encryptor` 와 `Decryptor` 도 thread-local 이어야 한다 — 이게 H-2 patch 가 한 일이다.

Config B (nGlobal=1024, 청크 5개, P=4) 의 Phase 3 wall-clock 은 0.94초 안팎이다. baseline 의 같은 조건은 21.5초. 회전 수의 비율 (1024/30 ≈ 34×) 과 OMP 분배 (5/⌈5/4⌉ = 2.5×) 의 곱이 약 85× 인데, 실측 22.4× 는 그 절반 정도다. 실측이 이론치를 못 따라가는 격차는 OMP context 스위칭, thread-local Evaluator 생성 비용, 그리고 청크별 작업 불균형 (한 batch 가 5 청크라 마지막 batch 의 작업이 비대칭) 에서 온다.

## 3.7 baby step 사전 계산의 메모리

baby step 사전 계산은 `m₁` 개의 ciphertext 를 thread-local 로 들고 있는다. P=4, m₁=32, ciphertext 한 개당 약 0.5 MB → 한 thread 당 16 MB, 4 thread 동시면 64 MB. nGlobal=4096 에선 m₁=64, ciphertext 가 더 커지므로 동시 peak 가 수백 MB 까지 간다. 통합 spec sec 2.3 의 메모리 표는 이 동시 peak 를 별도 행으로 분리해 두었다.

baby step 의 재사용 가능성은 흥미로운 후속 연구거리다 — Phase 5 의 멱법 반복 10 회 사이에 같은 baby step 을 재사용할 수 있으면 회전이 10 배 줄어든다. 하지만 그러려면 CKKS 의 useful depth 가 10 단계의 곱셈을 견뎌야 하는데, 현재 coeff_modulus `{60,45,45,60}` 으론 그게 안 된다. 그래서 Phase 5 가 매 iter 마다 *복호 후 재암호* 를 하는 단순화가 들어가 있다 — 다음 절 참조.

## 3.8 출력 — 부분 그래프의 trust 분포

Phase 3 의 출력은 K 개의 ciphertext, 각각 한 청크에 들어있던 batch_size 명의 평가 대상에 대해 *N 차원의 trust 분포* 를 들고 있다. c 번째 평가 대상이 청크의 c-번째 슬롯 묶음에 있다면, 그 ciphertext 의 슬롯 `[c · 2N, c · 2N + N)` 에는 "이 대상이 다른 N 개의 노드에게 받는 trust 의 1+2-hop 누적" 이 들어있다.

다음 단계 (Phase 4) 는 이 분포를 복호해서 상위 nSub 명을 골라낸다.
