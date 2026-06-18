# 2. Phase 1 — 그래프 전처리

Phase 1 은 BitcoinOTC csv 를 받아 두 가지를 만든다. 하나는 Phase 5 에서 부분 그래프 구성에 쓰일 1-hop 가중치 행렬 `M_pub`, 다른 하나는 Phase 3 PIR 의 평문 데이터인 BsgsDiag 리스트다. 이 문서는 한 줄의 csv 가 어떤 변환을 거쳐 어떤 형태로 끝나는지 추적한다.

코드 참조 위치는 통합 (`feat/bgsg-sparse-integrated`) 의 `CipherRank.cpp` 기준이다.

## 2.1 csv 한 줄이 들어왔을 때

다음 한 줄을 예로 들자.

```
6,2,4,1289241911.72836
```

`CipherRank.cpp:354–390` 의 파서는 이 줄을 다음과 같이 다룬다.

1. `parts[0]=6`, `parts[1]=2`, `parts[2]=4`, `parts[3]` 은 `int` 변환 실패 → `catch(...){}` 로 무시된다 (소수점 때문). 그러나 `parts[2]>=2` 필터는 통과한다.
2. 그러므로 이 행은 `rawEdges.push_back({6, 2, 4, 1289241911})` 로 저장되고, `frequency[6]++; frequency[2]++` 가 일어난다. `maxTime` 변수에는 모든 행을 본 후의 최대 시각이 남는다.

원본 35,592 행을 다 훑으면 `parts[2] >= 2` 를 통과하는 행이 정확히 **11,981 개**, 등장 노드 (`frequency` 의 키 집합 크기) 가 **3,302 개**, `maxTime` ≈ 1453684323 (2016년 1월) 이다.

음수 평점을 통째로 버린다는 점은 의미 모델에 직접 영향을 준다. 신뢰가 아니라 *불신* 신호를 가진 간선이 입력 단계에서 사라지므로, 자연 sybil 의 검출이 weight ≥ 2 신호만으로 이뤄지게 된다. 5절 ("엣지케이스") 에서 다시 다룬다.

## 2.2 빈도 기준 top-N 선택

`frequency` 는 한 노드가 *송신자나 수신자로 등장한 횟수* 다. 즉 in-degree 와 out-degree 의 합이다. 코드의 `CipherRank.cpp:381–386`:

```cpp
vector<pair<int,int>> freqVec(frequency.begin(), frequency.end());
sort(freqVec.begin(), freqVec.end(),
     [](auto& a, auto& b){ return a.second > b.second; });
unordered_map<int,int> globalNodeToIndex;
for (size_t i = 0; i < min(freqVec.size(), (size_t)nGlobal); i++)
    globalNodeToIndex[freqVec[i].first] = i;
```

이렇게 `nGlobal=1024` 면 상위 1024 명만 `globalNodeToIndex` 에 매핑된다. 그 외 노드는 *이후 모든 계산에서 존재하지 않는 것처럼 다뤄진다*. `requestedWalletIds` 에 있더라도 매핑에 없으면 그 줄은 `[WARNING] Wallet ID X is out of range.` 로 떨어지고 평가에서 제외된다.

상위 1024 위 노드의 frequency 는 BitcoinOTC 에서 대체로 6~8 정도다. 자연 sybil 후보 (음수 평점을 다수 받는 노드) 는 frequency 가 이 컷오프 이상이어야 평가 가능하다는 뜻이다. 5절의 사용자 식별 절차는 이 컷오프 이상의 노드들에 한정해서 sybil 후보를 골랐다.

`unordered_map` 자체는 빌드별로 해시 순서가 결정적이지 않을 수 있으나 (Q4 baseline 으로 후속 reduce 단계에서 sorted vector 로 직렬화한다), `globalNodeToIndex` 의 인덱스 자체는 `freqVec` 의 정렬 결과 → 빈도 동률일 때 unordered_map 노드 순서 → 결정적인지 의문이 남는다. 다행히 BitcoinOTC 에서 상위 1024 명의 빈도가 거의 모두 다르므로, 실측에선 cross-run 인덱스가 안정적이었다. 더 험한 데이터셋에서는 `std::map` 으로 교체해 안전을 보강해야 한다.

## 2.3 시간 감쇠

신뢰 평점은 시간이 지날수록 약화되어야 합리적이다. 코드는 반감기 1년의 지수 감쇠를 쓴다.

`CipherRank.cpp:407`:

```cpp
double HALF_LIFE = 365.0 * 24.0 * 60.0 * 60.0;        // 1 year in seconds
double decay = pow(0.5, (maxTime - edge.time) / HALF_LIFE);
double w = edge.weight * decay;
```

예를 들어 위 첫 줄 (`time = 1289241911`, weight = 4) 이 `maxTime ≈ 1453684323` 보다 5.21 년 전이라면 decay = 0.5^5.21 ≈ 0.0269, w = 4 × 0.0269 ≈ 0.108. 같은 +4 평점이라도 최근 거래라면 w ≈ 4, 6년 전 거래라면 w ≈ 0.06 정도가 된다. 이 양은 다음 단계의 가지치기 임계값 θ = 0.05 의 직접적인 기준이 된다 — 너무 오래된 +2 평점은 자동으로 2-hop 전파에서 잘리고, 최근 +3 평점은 그대로 살아남는다.

## 2.4 1-hop 행렬 M_pub

`outM_pub` 은 행이 수신자, 열이 송신자인 가중치 행렬이다. `outM_pub[tgt][src] = w` 는 "송신자 src 가 수신자 tgt 에게 시간 감쇠된 가중치 w 만큼의 신뢰를 보냈다"를 뜻한다. 같은 (src, tgt) 쌍에 여러 거래가 있으면 누적된다 (`+=`). 같은 데이터셋에서 (1, 15, 1) 과 (1, 15, 4) 가 모두 있을 수 있고, 둘 다 weight ≥ 2 필터를 통과하는 것만 누적된다.

통합 브랜치에서는 같은 루프에서 인접 리스트 `outAdj` 도 함께 만든다 (`CipherRank.cpp:412–423`):

```cpp
for (const auto& edge : rawEdges) {
    if (globalNodeToIndex.count(edge.src) && globalNodeToIndex.count(edge.tgt)) {
        int srcIdx = globalNodeToIndex[edge.src];
        int tgtIdx = globalNodeToIndex[edge.tgt];
        double decay = pow(0.5, (maxTime - edge.time) / HALF_LIFE);
        double w = edge.weight * decay;
        outM_pub[tgtIdx][srcIdx] += w;
        outAdj[srcIdx].push_back({tgtIdx, w});
    }
}
```

`outM_pub` 은 Phase 5 가 부분 그래프를 다시 끌어올 때 쓴다 (Q5 적용 후 dense 가 아닌 sparse 표현, `vector<unordered_map<int,double>>`). `outAdj[srcIdx]` 는 송신자별 출간선 리스트로, 다음 절의 2-hop 누적의 기본 자료구조다.

## 2.5 2-hop 누적 — A2 의 의미 변경

baseline 의 Phase 1 은 마무리로 `M_total = outM_pub + outM_pub · outM_pub` 의 N × N × N 곱을 직접 한다. 이는 *2-hop 전파의 모든 경로* 를 합산하는 셈인데, 신뢰 모델로 보면 *모든* 1-hop 을 동일하게 2-hop 으로 전파한다는 의미다.

A2 와 B 는 이 부분을 다음과 같이 바꾼다. 모든 src 에 대해, src 의 출간선 (mid, w₁) 을 훑으며 (`CipherRank.cpp:440–451`)

```cpp
for (const auto& [mid, w1] : outAdj[src]) {
    int d1 = (src - mid + nGlobal) % nGlobal;
    localDiag[d1][mid] += beta1 * w1;            // 1-hop, M_pub[mid][src]

    if (w1 < prune_threshold) continue;           // 약한 1-hop은 2-hop 전파 X

    for (const auto& [dst, w2] : outAdj[mid]) {
        int d2 = (src - dst + nGlobal) % nGlobal;
        localDiag[d2][dst] += beta2 * w1 * w2;   // β₂-가중 2-hop, M_pub^2[dst][src]
    }
}
```

이 루프가 만들어내는 양 `localDiag[d][row]` 의 의미를 풀어보자. 인덱스 `d = (src - row + N) mod N` 는 행 `row` 에서 열이 `(row + d) mod N = src` 가 되는, 즉 행렬 `M_pub[row][src]` 의 위치에 해당한다.

- 1-hop 누적: src 가 (`row + d`) 에 해당, mid 가 row 위치. 따라서 `localDiag[d1][mid] += β₁ · w₁ = β₁ · M_pub[mid][src]`. 모든 src 를 합산하면 `localDiag[d]` 는 1-hop 행렬의 d-번째 대각선과 같아진다.
- 2-hop 누적: (src, mid, dst) 경로. `M_pub²[dst][src] = Σ_k M_pub[dst][k] · M_pub[k][src] = Σ_mid w(mid→dst) · w(src→mid) = Σ_mid w₂ · w₁`. β₂·w₁·w₂ 를 `localDiag[d2][dst]` 에 누적하면, 결국 `localDiag[d]` 는 β₂ · `M_pub²` 의 d-번째 대각선과 같아진다.

따라서 정확히는 다음 변환이 이뤄진다.

```
sparseDiag[d][row] = β₁ · M_pub[row][row+d] + β₂ · M_pub²[row][row+d]   (단, 조건부 가지치기)
```

baseline 은 β₁ = β₂ = 1, 가지치기 없음. A2 와 B 의 기본값은 β₁ = 1.0, β₂ = 0.30, θ = 0.05. *알고리즘 등가성* 만 보고 싶다면 B 를 β₁ = β₂ = 1.0, θ = 0 으로 돌리면 된다 (이게 R1'' 검증 모드 = B-C2 다).

가지치기의 효과를 구체적으로 보자. 위에서 본 6 년 전 +4 평점의 시간 감쇠 결과는 w₁ ≈ 0.108 로, θ = 0.05 보단 크다. 따라서 그 간선은 2-hop 으로 전파된다. 반대로 9 년 전 +2 평점은 w₁ ≈ 0.5 × 2 = 0.0039 ≈ 0 으로 떨어지므로 2-hop 전파는 중단된다. θ 는 결국 "몇 년 전까지를 신뢰의 다리로 인정할 것인가" 의 정량이다.

## 2.6 OpenMP 와 결정적 합산 — B3 + Q4

위 루프는 src 에 대한 외부 분배가 직관적이지만, 여러 스레드가 `sparseDiag[d][row]` 를 동시에 갱신하면 race 가 생긴다. 통합 브랜치는 thread-local 누적 + thread_id 순서의 sequential reduce 로 처리한다 (`CipherRank.cpp:436–474`).

```cpp
#pragma omp parallel
{
    int tid = omp_get_thread_num();
    auto& localDiag = tlSparseDiag[tid];
    #pragma omp for schedule(static)
    for (int src = 0; src < nGlobal; src++) {
        // ... 위 루프
    }
}

// thread_id 0..P-1 순서로 std::map 에 합산 → row 오름차순 정렬 보장
vector<map<int,double>> merged(nGlobal);
for (int t = 0; t < num_threads; t++)
    for (int d = 0; d < nGlobal; d++)
        for (auto& [row, val] : tlSparseDiag[t][d])
            merged[d][row] += val;

// 0 인 항목 제거 (β₂=0 케이스의 transparent ciphertext 회피)
for (int d = 0; d < nGlobal; d++)
    for (auto& [row, val] : merged[d])
        if (val != 0.0) sparseDiag[d].emplace_back(row, val);
```

세 가지 짚을 점이 있다.

1. **결합 순서가 thread_id 순.** 부동소수점 덧셈은 결합법칙을 *완전히* 만족하지 않으므로, 같은 입력에 대해 다른 합산 순서로 같은 결과를 보장하려면 합산 순서 자체를 고정해야 한다. P = 4 든 P = 8 이든 cross-run 결과가 일치해야 R9'' / R11'' 가 의미를 갖는다.
2. **row 오름차순 정렬.** `std::map` 으로 합산한 결과를 `vector<pair<int,double>>` 로 옮기면 자동으로 row 오름차순이다. 이후 BsgsDiag 인코딩 단계에서 정해진 순서로 슬롯에 기록되므로 동일 입력 → 동일 평문 직렬화가 보장된다.
3. **val == 0 항목 drop.** β₂ = 0 이면 2-hop 기여가 모두 0 이지만, 누적 자체는 일어나서 `(row, 0.0)` 가 남는다. 이걸 그대로 두면 BsgsDiag 의 plaintext 가 모두 0 이 되고, BSGS 의 `multiply_plain` 결과가 전부 0 인 ciphertext (SEAL 용어로 *transparent*) 가 되어 예외가 던져진다. fix 는 단순히 `val != 0.0` 만 남기는 것으로 충분하다. 자세한 경위는 5절에서 다시 다룬다.

## 2.7 BsgsDiag 와 Q7 패딩

마지막 단계는 `sparseDiag` 의 대각선 d 를 BSGS 의 baby/giant 분해에 맞춰 `BsgsDiag{i, j, Plaintext}` 로 인코딩하는 일이다 (`CipherRank.cpp:476–500`):

```cpp
for (int j = 0; j < m2; j++) {
    for (int i = 0; i < m1; i++) {
        int d = j * m1 + i;
        if (d >= nGlobal) continue;
        if (sparseDiag[d].empty()) continue;

        vector<double> diag(slot_count, 0.0);
        for (size_t c = 0; c < batch_size; c++) {
            for (const auto& [row, val] : sparseDiag[d]) {
                int slot_idx = (row + j * m1) % nGlobal;
                diag[c * pirBlockSize + slot_idx] = val;
                diag[c * pirBlockSize + slot_idx + nGlobal] = val;   // Q7 padding
            }
        }
        // ... encode + push BsgsDiag
    }
}
```

d 의 의미는 3절에서 본격적으로 다루지만 골조만 미리 적자: BSGS 는 [0, N) 의 대각선 d 를 `d = j · m₁ + i` 로 쪼개고, baby step i 는 *입력 ciphertext* 쪽에서, giant step j 는 *plain diagonal* 쪽에서 회전을 흡수한다. 그래서 같은 d 의 평문이라도 j 에 따라 *원래 row 가 향해야 할 슬롯 위치* 가 다르다 — 정확히 `slot_idx = (row + j · m₁) mod N` 이다.

`Q7 padding` 은 한 청크의 2N 슬롯 중 뒤쪽 N 슬롯에 앞쪽과 같은 값을 복제해 넣는 트릭이다. 이게 왜 필요한지는 3절의 "청크 경계와 회전 안전" 절에서 본격적으로 풀어쓰지만, 한 줄 요약은 "BSGS giant step 회전이 청크 경계에 걸칠 수 있어, 청크 안쪽으로 wrap-around 한 값이 의도된 값과 정확히 같도록 미리 두 번 적어두는 것"이다.

빈 대각선 (예: β₂=0 의 영향으로 0 인 항목이 모두 제거되어 vector 가 비는 d) 은 인코딩을 통째로 건너뛴다. 이 경우 그 d 는 BsgsDiag 리스트에 등장하지 않으므로 Phase 3 의 plain mult 단계에서 자연스럽게 빠진다. β₂=0, θ=0 으로 실행하면 N=1024 에서 D_sparse 는 1020 (네 개의 d 가 1-hop 만으로 비어 있음) 으로 나온다.

## 2.8 출력의 형상

Phase 1 의 최종 두 출력은 다음과 같다.

- `outM_pub`: nGlobal 개의 `unordered_map<int, double>` (Q5). row 별로 sparse 표현. Phase 5 가 인덱스 두 개로 random access.
- `pirDiagonals`: `vector<BsgsDiag>`, 길이는 D_sparse. 각 원소가 baby/giant 인덱스 (i, j) 와 인코딩된 CKKS plaintext 를 들고 있다.

이 두 출력이 다음 두 단계 (Phase 3 의 PIR, Phase 5 의 PageRank) 의 *전체* 입력 데이터다. 그 외에는 클라이언트 측의 (one-hot 으로 변환될) 평가 대상 인덱스 뿐이다.

## 2.9 손으로 따라가는 N=4 트레이스

1 절 1.7 의 6 줄짜리 csv 를 들고 Phase 1 의 출력 직전까지 직접 따라간다. 모든 시각이 같다는 가정에서 시간 감쇠가 1.0 이라 raw weight 그대로 살아남는 점만 미리 짚어두자.

### 2.9.1 outAdj 와 outM_pub

`globalNodeToIndex` 적용 후 6 줄이 다음과 같이 변환된다.

| 원본 (src, tgt, w) | (srcIdx, tgtIdx, w) |
|---|---|
| (10, 20, 4) | (0, 2, 4) |
| (10, 30, 3) | (0, 1, 3) |
| (20, 30, 5) | (2, 1, 5) |
| (30, 40, 2) | (1, 3, 2) |
| (40, 10, 3) | (3, 0, 3) |
| (30, 10, 4) | (1, 0, 4) |

`outAdj[src]` 는 src 에서 나가는 (tgt, w) 의 리스트로 채워진다.

```
outAdj[0] = [(2, 4), (1, 3)]     // wallet 10 의 출간선
outAdj[1] = [(3, 2), (0, 4)]     // wallet 30
outAdj[2] = [(1, 5)]             // wallet 20
outAdj[3] = [(0, 3)]             // wallet 40
```

같은 루프에서 누적되는 `outM_pub[tgt][src] += w` 를 4×4 dense 로 그리면 다음이다 (행 = 수신자, 열 = 송신자).

```
         src=0  src=1  src=2  src=3
tgt=0  [   0      4      0      3   ]
tgt=1  [   3      0      5      0   ]
tgt=2  [   4      0      0      0   ]
tgt=3  [   0      2      0      0   ]
```

이 행렬이 곧 `M_pub`. 열 j 는 "wallet j 가 *내보내는* 신뢰 분포", 행 i 는 "wallet i 가 *받는* 신뢰 분포" 다.

### 2.9.2 sparseDiag 누적 — 정의대로 손으로

β₁ = 1.0, β₂ = 0.3, θ = 0.05 의 기본 모드. 본 예제의 모든 w₁ 이 정수 (≥ 2) 라 θ 가지치기는 단 한 곳에서도 발동하지 않는다.

코드의 이중 루프를 src = 0, 1, 2, 3 순으로 펼친다 (한 스레드로 다 돌렸다 치고 thread-local 분리는 생략).

**src = 0 (wallet 10):**

- (mid=2, w₁=4): d₁ = (0 − 2 + 4) % 4 = 2 → `sparseDiag[2][2] += 4`
  - 2-hop: outAdj[2] = [(1, 5)]. dst=1, w₂=5: d₂ = 3 → `sparseDiag[3][1] += 0.3 · 4 · 5 = 6`
- (mid=1, w₁=3): d₁ = 3 → `sparseDiag[3][1] += 3` (위와 다른 경로) → 누적 9
  - 2-hop: outAdj[1] = [(3, 2), (0, 4)]
    - dst=3, w₂=2: d₂ = 1 → `sparseDiag[1][3] += 0.3 · 3 · 2 = 1.8`
    - dst=0, w₂=4: d₂ = 0 → `sparseDiag[0][0] += 0.3 · 3 · 4 = 3.6`

**src = 1 (wallet 30):**

- (mid=3, w₁=2): d₁ = 2 → `sparseDiag[2][3] += 2`
  - 2-hop: outAdj[3] = [(0, 3)]. dst=0, w₂=3: d₂ = 1 → `sparseDiag[1][0] += 0.3 · 2 · 3 = 1.8`
- (mid=0, w₁=4): d₁ = 1 → `sparseDiag[1][0] += 4` → 누적 5.8
  - 2-hop: outAdj[0] = [(2, 4), (1, 3)]
    - dst=2, w₂=4: d₂ = 3 → `sparseDiag[3][2] += 0.3 · 4 · 4 = 4.8`
    - dst=1, w₂=3: d₂ = 0 → `sparseDiag[0][1] += 0.3 · 4 · 3 = 3.6`

**src = 2 (wallet 20):**

- (mid=1, w₁=5): d₁ = 1 → `sparseDiag[1][1] += 5`
  - 2-hop: outAdj[1] = [(3, 2), (0, 4)]
    - dst=3, w₂=2: d₂ = 3 → `sparseDiag[3][3] += 0.3 · 5 · 2 = 3`
    - dst=0, w₂=4: d₂ = 2 → `sparseDiag[2][0] += 0.3 · 5 · 4 = 6`

**src = 3 (wallet 40):**

- (mid=0, w₁=3): d₁ = 3 → `sparseDiag[3][0] += 3`
  - 2-hop: outAdj[0] = [(2, 4), (1, 3)]
    - dst=2, w₂=4: d₂ = 1 → `sparseDiag[1][2] += 0.3 · 3 · 4 = 3.6`
    - dst=1, w₂=3: d₂ = 2 → `sparseDiag[2][1] += 0.3 · 3 · 3 = 2.7`

reduce 후 (= 위 누적 그대로) row 오름차순으로 정렬해서 펴면:

| d | sparseDiag[d] (row : val) |
|---:|---|
| 0 | { 0 : 3.6, 1 : 3.6 } |
| 1 | { 0 : 5.8, 1 : 5.0, 2 : 3.6, 3 : 1.8 } |
| 2 | { 0 : 6.0, 1 : 2.7, 2 : 4.0, 3 : 2.0 } |
| 3 | { 0 : 3.0, 1 : 9.0, 2 : 4.8, 3 : 3.0 } |

### 2.9.3 검산 — M_pub + 0.3 · M_pub² 의 대각선과 비교

위 누적이 *정의대로* 작동하는지 직접 확인한다. M_pub² 의 16 칸을 손으로 계산하면

| | j=0 | j=1 | j=2 | j=3 |
|---|---:|---:|---:|---:|
| i=0 | 12 | 6 | 20 | 0 |
| i=1 | 20 | 12 | 0 | 9 |
| i=2 | 0 | 16 | 0 | 12 |
| i=3 | 6 | 0 | 10 | 0 |

(예: M²[0][0] = 0·0 + 4·3 + 0·4 + 3·0 = 12. M²[0][1] = 0·4 + 4·0 + 0·0 + 3·2 = 6. M²[3][2] = 0·0 + 2·5 + 0·0 + 0·0 = 10. 나머지 동일한 방식.)

M_total = M_pub + 0.3 · M²:

```
[ 3.6   5.8   6.0   3.0 ]
[ 9.0   3.6   5.0   2.7 ]
[ 4.0   4.8   0.0   3.6 ]
[ 1.8   2.0   3.0   0.0 ]
```

d 번째 대각선 = `M_total[row][(row + d) mod 4]`:

- d = 0: (3.6, 3.6, 0, 0) — 0 이 아닌 것만 남기면 `{0: 3.6, 1: 3.6}`. **위 sparseDiag[0] 과 일치.** ✓
- d = 1: (5.8, 5.0, 3.6, 1.8). **sparseDiag[1] 과 일치.** ✓
- d = 2: (6.0, 2.7, 4.0, 2.0). **sparseDiag[2] 과 일치.** ✓
- d = 3: (3.0, 9.0, 4.8, 3.0). **sparseDiag[3] 과 일치.** ✓

전부 소수점 한 자리까지 정확히 일치한다 — *알고리즘이 정의한 변환이 그대로 코드에 옮겨졌다는 한 줄 증명이다.* N³ 의 dense 곱을 굳이 하지 않고 outAdj 위에서 같은 결과를 얻을 수 있는 이유의 시각적 확인이기도 하다.

### 2.9.4 BsgsDiag 인코딩과 Q7 패딩

N = 4 에서 BSGS 의 최적해는 m₁ = m₂ = 2 (`FindOptimalAsymmetricBSGS(4, 1.0)` 의 반환). 그러면 d 가 (j, i) 로 다음과 같이 쪼개진다.

| d | j (giant) | i (baby) |
|---:|---:|---:|
| 0 | 0 | 0 |
| 1 | 0 | 1 |
| 2 | 1 | 0 |
| 3 | 1 | 1 |

청크 하나, batch_size = 1, slot_count = 8 (= 2N) 의 단순 가정 하에 각 BsgsDiag 의 평문은 8 슬롯짜리 vector 다. 슬롯 위치는 `slot_idx = (row + j · m₁) mod N = (row + 2j) mod 4` 에 sparseDiag[d] 의 row→val 을 기록하고, **Q7 패딩** 으로 같은 위치 + N 에도 같은 값을 적는다.

(j=0, i=0) — d = 0, sparseDiag[0] = {0: 3.6, 1: 3.6}:

- row=0 → slot 0 ← 3.6, slot 0+4=4 에도 3.6
- row=1 → slot 1, 5 에 3.6
- vector: `[3.6, 3.6, 0, 0, 3.6, 3.6, 0, 0]`

(j=0, i=1) — d = 1, sparseDiag[1] = {0: 5.8, 1: 5.0, 2: 3.6, 3: 1.8}:

- slot_idx 가 row 그대로
- vector: `[5.8, 5.0, 3.6, 1.8, 5.8, 5.0, 3.6, 1.8]`

(j=1, i=0) — d = 2, sparseDiag[2] = {0: 6.0, 1: 2.7, 2: 4.0, 3: 2.0}:

- slot_idx = (row + 2) mod 4. row=0→2, row=1→3, row=2→0, row=3→1
- vector: `[4.0, 2.0, 6.0, 2.7, 4.0, 2.0, 6.0, 2.7]`

(j=1, i=1) — d = 3, sparseDiag[3] = {0: 3.0, 1: 9.0, 2: 4.8, 3: 3.0}:

- slot_idx = (row + 2) mod 4 동일 매핑
- vector: `[4.8, 3.0, 3.0, 9.0, 4.8, 3.0, 3.0, 9.0]`

이 네 vector 가 CKKS encode → `pirDiagonals` 의 네 BsgsDiag `{(i=0, j=0), (i=1, j=0), (i=0, j=1), (i=1, j=1)}` 로 캐싱된다. **D_sparse = 4 = N** 이라 sparsity = 0. 작은 그래프이고 모든 d 가 값이 0 이 아닌 entry 를 가져서 그렇다 — 실제 BitcoinOTC 에선 D_sparse 가 N 보다 작다. 3 절 3.9 에서 이 네 평문을 one-hot 과 BSGS 로 곱한다.
