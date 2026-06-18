# 4. Phase 4–6 — 부분 그래프와 동형 PageRank

Phase 4 와 Phase 5 는 한 단위로 묶어 보는 게 편하다. Phase 4 가 부분 그래프의 *어떤 노드를 살릴지* 를 결정하고, Phase 5 가 그 부분 그래프 위에서 PageRank 를 동형으로 굴린다. 마지막 Phase 6 은 평가 대상의 점수를 임계값과 비교해 verdict 를 낸다.

## 4.1 Phase 4 — 부분 그래프 인덱스 결정

Phase 3 의 출력은 청크별 ciphertext 다. 청크 c 안의 c'-번째 슬롯 묶음 `[c'·2N, c'·2N + N)` 에는 그 자리의 평가 대상이 다른 N 개 노드 각각에게 받는 trust 의 1+2-hop 누적 분포가 들어있다. Phase 4 는 이 ciphertext 들을 복호해서 (`CipherRank.cpp:599`) 슬롯 분포를 평문 vector 로 본 다음 (`CipherRank.cpp:603`), N 개 슬롯의 값을 내림차순으로 정렬해 상위 nSub 개를 고른다.

`CipherRank.cpp:620–636` 부분:

```cpp
for (size_t c = 0; c < (end_idx - start_idx); c++) {
    vector<Score> scores;
    for (int i = 0; i < nGlobal; i++) {
        double val = decodedNeighbors[c * pirBlockSize + i];
        val = round(val * 100000.0) / 100000.0;           // 양자화
        scores.push_back({i, val});
    }
    sort(scores.begin(), scores.end(), [](const Score& a, const Score& b) {
        if (abs(a.score - b.score) < 1e-6) return a.index < b.index;  // 결정적 tie-break
        return a.score > b.score;
    });
    vector<int> topNodes;
    for (int i = 0; i < nSub; i++) topNodes.push_back(scores[i].index);

    int targetGIdx = targetGlobalIndices[start_idx + c];
    if (find(topNodes.begin(), topNodes.end(), targetGIdx) == topNodes.end())
        topNodes[nSub - 1] = targetGIdx;                  // 대상이 누락되면 마지막 슬롯에 강제 삽입
    ...
}
```

여기서 짚을 점 셋.

1. **양자화 `round(val * 1e5) / 1e5`**: CKKS 의 복호 결과는 평문 정답에 `~2^-35` 수준의 노이즈가 얹힌 부동소수점이다. nSub 위치에 들어갈 두 노드의 점수가 *거의 같을 때*, 다음 줄의 비교가 노이즈로 흔들리면 cross-run 으로 다른 nSub 집합이 뽑힐 수 있다. round 와 1e-6 tie-break 은 이를 막는 결정적 정렬 장치다.
2. **대상 본인의 강제 포함**: PageRank 가 부분 그래프 안에서 평가 대상의 점수를 산출하므로, 평가 대상이 자기 부분 그래프 안에 *반드시* 있어야 한다. 외부 trust 가 부족해 top-nSub 에 들지 못한 경우 마지막 자리에 끼워넣는다. 이 강제 삽입은 평가 대상의 자기 PageRank 가 항상 정의되도록 보장하는 안전판이다.
3. **결과는 평문**: `topNodes` 가 평문이라는 사실은 *Phase 4 출력 자체가 평가 대상에 대한 정보 누설* 임을 뜻한다. 즉 클라이언트는 자기가 누구를 평가하는지 알고, top-nSub 도 알고, 그 다음 단계 (Phase 5) 에서 그 nSub 부분 행렬을 서버에게 던진다. 이 모델에선 서버가 *어떤 부분 그래프 위에서 계산하는지* 는 보지만 (그건 그래프가 평문이라 어차피 공개), 점수 결과는 끝까지 ciphertext 안에 머문다.

`outTopNodes` 와 `outTargetSubIdx` 가 Phase 5 의 입력이다. 후자는 *부분 그래프 안에서 평가 대상이 몇 번째 인덱스인지* 다. PageRank 출력 벡터의 `subIdx` 자리만 읽으면 평가 대상의 최종 점수가 된다.

## 4.2 부분 행렬과 PageRank 정규화

Phase 5 의 첫 단계는 부분 그래프의 가중치 행렬 `M_sub[c]` 를 만드는 일이다. 평가 대상 c 의 top-nSub 인덱스 집합 `topNodes` 를 가지고 `M_pub` 에서 nSub × nSub 부분만 잘라낸다 (`CipherRank.cpp:687–690`):

```cpp
for (size_t c = 0; c < num_targets; c++) {
    for (int i = 0; i < nSub; i++) {
        for (int j = 0; j < nSub; j++)
            all_M_sub[c][i][j] = SparseGet(M_pub, allTopNodes[c][i], allTopNodes[c][j]);
    }
```

(Q5 적용 후 `M_pub` 은 sparse 표현이므로 `operator[]` 가 아니라 `SparseGet` 으로 읽는다. `[]` 를 쓰면 미존재 키에 0 값을 *삽입* 해버려 const-safety 가 깨지고 메모리도 부풀어오른다. EB17 의 이유.)

다음에 column-stochastic 정규화를 한다. PageRank 의 transition matrix 는 "j 열의 합이 1" 이어야 한다.

```cpp
double alpha = 0.85, tele = (1.0 - alpha) / nSub;
for (int j = 0; j < nSub; j++) {
    double colSum = 0.0;
    for (int i = 0; i < nSub; i++) colSum += all_M_sub[c][i][j];
    if (colSum == 0.0) all_M_sub[c][j][j] = 1.0;             // dangling node 보정
    else for (int i = 0; i < nSub; i++) all_M_sub[c][i][j] /= colSum;
    for (int i = 0; i < nSub; i++)
        all_M_sub[c][i][j] = (alpha * all_M_sub[c][i][j]) + tele;
}
```

- **column normalization**: 한 열의 모든 가중치를 그 열의 합으로 나눈다. 그러면 j 열이 확률 분포가 된다.
- **dangling node**: j 노드의 outflow 가 모두 부분 그래프 *밖* 이면 colSum=0 이다. 그 경우 j 열을 *자기 자신* 에 100% 머무는 분포로 둔다. 이건 Stanford PageRank original paper 의 표준 처리다.
- **teleportation**: α=0.85 의 확률로만 random walk 를 따르고, 1-α=0.15 의 확률은 모든 노드 중 하나에 균일하게 점프한다. 이 균일 점프는 `tele = (1-α) / nSub` 으로 모든 (i, j) 셀에 더해진다. 따라서 정규화된 한 열은 (α · 정규화된 column) + (1-α/nSub · 1_vec) 형태가 된다.

α = 0.85 는 PageRank 의 관례적 기본값이다. 너무 큰 α 는 그래프 구조의 자기 반복 효과를 키우고 (사이클이 있으면 폭주), 너무 작은 α 는 그래프 정보를 사실상 무시하고 균일 분포에 수렴한다.

## 4.3 평문 멱법 반복 — 정답 비교용

Phase 5 는 먼저 평문 PageRank 를 10 번 돌려 "정답" 을 만든다 (`CipherRank.cpp:709–717`):

```cpp
int ITERATIONS = 10;
for (int iter = 1; iter <= ITERATIONS; iter++) {
    for (size_t c = 0; c < num_targets; c++) {
        vector<double> nextV(nSub, 0.0);
        for (int j = 0; j < nSub; j++) {
            for (int i = 0; i < nSub; i++)
                nextV[i] += all_M_sub[c][i][j] * all_plainV[c][j];
        }
        all_plainV[c] = nextV;
    }
}
```

초기 벡터는 균일 분포 `V_0 = (1/n, ..., 1/n)`. 매 iter 마다 `V ← M_sub · V`. 10 iter 후 `V` 의 `subIdx` 자리가 평가 대상의 평문 PageRank 점수다.

평문 PageRank 가 PIR + FHE 측 점수와 어차피 비교될 거라면 굳이 따로 돌릴 필요가 있나? 두 가지 이유다. 첫째, Phase 6 의 정밀도 검증 출력에 `Precision Error = |fheScore - groundTruthScore|` 를 찍기 위함이다 (단일 머신 측정 시나리오에서만 의미가 있는 진단). 둘째, *부분 그래프가 동일하다면* 평문과 동형의 결과가 일치해야 한다는 가정 자체가 검증 대상이다 — CKKS 노이즈가 누적될수록 동형 결과는 평문에서 멀어지므로, 둘의 차이를 보는 게 R1''/R2''/R6'' 의 핵심 지표다.

## 4.4 동형 멱법 반복 — 회전 + 평문 곱 + 누적

Phase 5 의 동형 부분은 청크 루프 안에 들어있다. 한 청크당 다음 시퀀스를 ITER 회 반복한다.

1. 현재 logical V (평문) 를 CKKS 로 인코딩 + 암호화.
2. baby step 사전 계산 (m₁ - 1 회의 회전).
3. j = 0..m₂ - 1 에 대해, 그 j 의 BsgsDiag 들과의 평문 곱·rescale·누적을 한 다음 `j · m₁` 만큼 회전, 전체 합산.
4. 결과 복호 + 디코딩 → 새 logical V (평문).
5. clip + 재정규화: 음수 슬롯을 0 으로 자르고, 합이 0 이 아니면 sum-to-1 으로 다시 맞춤. 다음 iter 의 인코딩 입력.

수식으로 보면

```
y = M_sub · V    (CKKS 위에서 BSGS 로 동형 계산)
V_new = clip(decrypt(y), 0) / Σ clip(...)
```

평문 PageRank 와 동치인 부분은 1–3 단계, 단순화가 들어간 곳은 4–5 단계다. 매 iter 의 *끝* 에서 평문으로 떨어졌다가 다음 iter 의 *시작* 에서 다시 암호화한다. 이걸 *decrypt → re-encrypt loop* 라 부르자.

## 4.5 왜 매 iter 복호 + 재암호인가

진짜 PIR 프로토콜이라면 서버는 secret_key 를 가질 수 없으므로 *복호가 안 된다*. 그럼 평문으로 떨어지지 않고 ciphertext 만으로 ITER 회의 PageRank 를 돌려야 한다. 매 iter 의 `M_sub · V` 는 동형 곱셈이 한 번씩이고, 그 곱셈은 modulus chain 의 prime 을 하나씩 소모한다.

CipherRank 의 CKKS 파라미터 (`CipherRank.cpp:289`):

```cpp
parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 45, 45, 60 }));
```

는 useful multiplicative depth 가 약 2 다. ITER = 10 의 동형 곱셈을 지속하려면 필요한 depth 는 약 10. depth 2 의 ciphertext 로 10 단계를 가려면 bootstrapping 이 필요하다. SEAL CKKS 4.1.2 는 bootstrapping 을 지원하지 않는다.

그 대안이 매 iter *복호 + 재암호* 다. 평문으로 떨어지면 CKKS 노이즈가 0 으로 초기화되고, 다시 암호화하면 ciphertext 의 depth 가 full 로 회복된다. 단점은 명확하다 — 서버에 secret_key 가 있어야 하고, 그 결과 *진짜 PIR 위협 모델* 이 아니라 *단일-당사자 측정 시나리오* 가 된다. 본 코드의 모든 측정값이 그 가정 위에 서 있음을 위협 모델 caveat 으로 명시했다 (1절 1.4, 통합 spec sec 1 의 Caveat 박스).

## 4.6 Phase 5 의 BSGS — Phase 3 와 어떻게 다른가

Phase 5 도 `BsgsDiag` 인코딩 + baby/giant 분해를 쓴다. 다만 차원이 N 이 아니라 n = nSub 다. 통합 브랜치의 기본값으로 nSub = 256, m₁ = m₂ = 16, 회전 총합 30 이다. baseline Phase 5 가 매 iter 256 회의 회전을 도므로, BSGS 이득은 ITER × 회전수 비 = 10 × (256/30) ≈ 85× 가 된다 (단 실측은 약 12× — Phase 1 의 OMP 가 한 batch 안에서 청크 5 개 × 4 thread 의 부조화 비용을 함께 받기 때문).

`BsgsDiag` 의 인코딩 자체는 매 청크마다 (= 매 청크의 부분 행렬마다) 새로 만들어진다 (`CipherRank.cpp:743–762`). Phase 1 의 BsgsDiag 가 N 차원 전역 행렬 한 번 만에 끝나는 것과 다르다 — 부분 행렬은 청크별로 다르고, 그 행렬의 nSub 개 대각선을 매번 인코딩해야 한다.

`if (val > 0.0) isZero = false;` 식의 영-skip 가드는 그대로 들어있다. 부분 그래프의 한 대각선이 *완전히 0* 이면 그 d 의 BsgsDiag 를 만들지 않는다. 이는 회전·곱·덧셈 횟수의 데이터 의존성을 만들지만, 부분 그래프가 평가 대상의 함수이므로 평가 대상별로 약간 다른 wall-clock 이 나올 수 있다 (단일-당사자 측정 시나리오에선 무관).

## 4.7 매 iter 의 clip + 재정규화

매 iter 끝의

```cpp
for (int i = 0; i < nSub; i++) {
    double val = max(0.0, decoded[c * prBlockSize + i]);
    ...
}
```

는 두 가지를 한다. 첫째, 음수가 된 슬롯을 0 으로 자른다. PageRank 의 확률 벡터는 반드시 비음수여야 하고, CKKS 노이즈로 인해 0 근처의 값이 음수로 떨어진 경우가 있을 수 있다. 둘째, `sum == 0.0` 이면 균일 분포로 리셋, 아니면 sum-to-1 정규화. 정규화는 매 iter 후의 PageRank 벡터를 확률 분포로 강제하는 안전판이다 — 평문 PageRank 에서는 자연스럽게 보존되지만, 동형 위의 노이즈 누적과 column normalization 의 미세 오차를 고려해 명시적으로 한 번 더 정규화한다.

## 4.8 Phase 6 — verdict

10 iter 후의 `logicalV[c][allTargetSubIdx[c]]` 가 평가 대상 c 의 FHE 측 점수다. 평문 측 `all_plainV[c][allTargetSubIdx[c]]` 가 정답이고, 둘의 차이가 `Precision Error` 다.

verdict 는 단순하다 (`CipherRank.cpp:826`):

```cpp
if (fheScore >= 0.0150) cout << "[APPROVED] Minimum threshold met.";
else cout << "[REJECTED] Insufficient trust score.";
```

임계값 0.0150 은 통계적 정당화 없이 코드에 하드코딩되어 있다. 부분 그래프 안에서 균일 분포 (1/nSub) 가 매 iter 의 시작점이므로, 평가 대상이 "랜덤보다 의미 있게 높은 점수" 를 받으려면 다른 노드들로부터의 trust inflow 가 그래프 구조상 평가 대상에게 집중되어야 한다. nSub = 64 의 경우 균일 점수는 1/64 ≈ 0.0156, nSub = 256 의 경우 1/256 ≈ 0.0039 다. 그러니 0.0150 임계값은 nSub 가 작을 땐 "약간 평균보다 위", 클 땐 "평균의 4 배 위" 로 의미가 변한다. 이 임계값 자체는 후속 작업에서 nSub 함수로 파라미터화 해야 한다고 spec 의 R6 가 지적해두었다.

베이스라인과 통합 B 의 verdict 가 같은 입력에서 다르게 나오는 사례는 1절 1.6 의 Wallet 4 를 참고. 이는 BSGS 의 노이즈가 아니라 *β·θ 의 의미 모델 변경* 으로 Phase 3 가 다른 부분 그래프를 뽑아온 결과다 — Phase 4 의 top-nSub 가 달라지면 Phase 5 의 부분 행렬도 달라지고, 그 위의 PageRank 도 달라진다.

## 4.9 같은 예제 — Phase 4 의 top-K, Phase 5 의 멱법 반복, verdict

3 절 3.9 끝에서 얻은 PIR 결과 `[5.8, 3.6, 4.8, 2.0]` 가 wallet 30 에 대한 N=4 차원 trust 분포다. 여기서부터 부분 그래프 결정과 동형 PageRank 까지 트레이스를 이어간다. nSub = 3 으로 두자 (작아야 손으로 따라가기 쉽다).

### 4.9.1 양자화와 top-3 결정

복호 결과 vector 의 앞 4 슬롯 `[5.8, 3.6, 4.8, 2.0]` 에 `round(val * 1e5) / 1e5` 양자화를 적용해도 본 예제는 정수 + 한자리 소수라 그대로 살아남는다 (CKKS 노이즈는 약 10⁻⁹ 수준).

(idx, score) 쌍: [(0, 5.8), (1, 3.6), (2, 4.8), (3, 2.0)].

내림차순 정렬: [(0, 5.8), (2, 4.8), (1, 3.6), (3, 2.0)].

상위 3 (nSub = 3): `topNodes = [0, 2, 1]`. 평가 대상의 globalIdx = 1 이 topNodes 안에 있고, subIdx = 2.

(만약 wallet 30 이 자기 top-3 에 못 들었다면 코드가 `topNodes[nSub-1] = 1` 로 마지막 자리에 강제 삽입했을 것이다. 본 예제는 그럴 일이 없지만, 일반 케이스에선 이 강제 삽입이 *평가 대상의 자기 PageRank 점수가 항상 정의되도록* 보장한다.)

### 4.9.2 부분 행렬 M_sub

`M_sub[i][j] = M_pub[topNodes[i]][topNodes[j]]`. topNodes = [0, 2, 1] 로 9 칸을 추출.

| | j=0 (idx 0) | j=1 (idx 2) | j=2 (idx 1) |
|---|---:|---:|---:|
| i=0 (idx 0) | M_pub[0][0]=0 | M_pub[0][2]=0 | M_pub[0][1]=4 |
| i=1 (idx 2) | M_pub[2][0]=4 | M_pub[2][2]=0 | M_pub[2][1]=0 |
| i=2 (idx 1) | M_pub[1][0]=3 | M_pub[1][2]=5 | M_pub[1][1]=0 |

행렬 형태:

```
M_sub = [ 0   0   4 ]
        [ 4   0   0 ]
        [ 3   5   0 ]
```

(주의: PageRank 의 transition 은 *1-hop* 행렬 `M_pub` 위에서 도는 것이고, top-K 결정만 1+2-hop 의 `M_total` 으로 한다. 이 비대칭이 의도된 설계인가는 spec 의 미답 자리 중 하나지만, 코드는 분명히 이렇게 되어있다.)

### 4.9.3 column normalization 과 teleport

각 열의 합을 구해 나누고 (column-stochastic), teleport 를 더한다.

- col 0 합 = 0 + 4 + 3 = 7. 정규화: [0, 4/7, 3/7] ≈ [0, 0.5714, 0.4286]
- col 1 합 = 0 + 0 + 5 = 5. 정규화: [0, 0, 1]
- col 2 합 = 4 + 0 + 0 = 4. 정규화: [1, 0, 0]

dangling 없음 (어느 col 도 합 = 0 아님). α = 0.85, tele = (1 − 0.85) / 3 = 0.05.

transition matrix T = α · M_sub_norm + tele · 1:

```
T ≈ [ 0.0500   0.0500   0.9000 ]
    [ 0.5357   0.0500   0.0500 ]
    [ 0.4143   0.9000   0.0500 ]
```

각 열의 합 확인: 0.05 + 0.5357 + 0.4143 = 1.0000 ✓. 0.05 + 0.05 + 0.9 = 1.0 ✓. 0.9 + 0.05 + 0.05 = 1.0 ✓. column-stochastic 보존.

### 4.9.4 멱법 반복 10 회

초기 V₀ = [1/3, 1/3, 1/3] ≈ [0.3333, 0.3333, 0.3333].

**Iter 1**: V₁ = T · V₀

- V₁[0] = 0.05·0.3333 + 0.05·0.3333 + 0.9·0.3333 = 0.3333
- V₁[1] = 0.5357·0.3333 + 0.05·0.3333 + 0.05·0.3333 = 0.2119
- V₁[2] = 0.4143·0.3333 + 0.9·0.3333 + 0.05·0.3333 = 0.4548

**Iter 2**: V₂ = T · V₁

- V₂[0] = 0.05·0.3333 + 0.05·0.2119 + 0.9·0.4548 = 0.4365
- V₂[1] = 0.5357·0.3333 + 0.05·0.2119 + 0.05·0.4548 = 0.2119
- V₂[2] = 0.4143·0.3333 + 0.9·0.2119 + 0.05·0.4548 = 0.3516

(이후는 같은 곱셈의 반복이라 산수 결과만 적는다.)

| iter | V[0] | V[1] | V[2] | 합 |
|---:|---:|---:|---:|---:|
| 0 | 0.3333 | 0.3333 | 0.3333 | 1.0000 |
| 1 | 0.3333 | 0.2119 | 0.4548 | 1.0000 |
| 2 | 0.4365 | 0.2119 | 0.3516 | 1.0000 |
| 3 | 0.3488 | 0.2620 | 0.3891 | 0.9999 |
| 4 | 0.3807 | 0.2194 | 0.3998 | 0.9999 |
| 5 | 0.3898 | 0.2349 | 0.3752 | 0.9999 |
| 6 | 0.3689 | 0.2393 | 0.3917 | 0.9999 |
| 7 | 0.3830 | 0.2292 | 0.3878 | 1.0000 |
| 8 | 0.3796 | 0.2360 | 0.3844 | 1.0000 |
| 9 | 0.3767 | 0.2344 | 0.3889 | 1.0000 |
| 10 | 0.3806 | 0.2330 | 0.3865 | 1.0001 |

(합의 마지막 자리 오차는 반올림 누적. 매 iter 끝의 sum-to-1 정규화 단계가 이 오차를 다시 1.0 으로 맞춰준다.)

10 iter 후 V ≈ [0.3806, 0.2330, 0.3865]. 1 자리 진동이 남아있는데 그래프가 워낙 작아서 (n = 3) 그렇다. 실 BitcoinOTC 의 nSub = 64/256 위에선 약 5 iter 면 10⁻⁴ 까지 수렴한다.

### 4.9.5 평가 대상의 점수와 verdict

target wallet 30 의 subIdx = 2 (4.9.1 에서). 따라서 fheScore = V₁₀[2] ≈ 0.3865.

verdict: 0.3865 ≥ 0.0150 → **[APPROVED] Minimum threshold met.**

물론 이 점수가 인상적으로 큰 것은 nSub = 3 이라는 비현실적으로 작은 부분 그래프 위에서, wallet 30 이 wallet 10 과 wallet 20 모두에게서 직접 trust 를 받기 때문이다. 실 BitcoinOTC 의 nSub = 64 에선 균일 분포가 1/64 ≈ 0.0156 이라, "임계값 0.0150" 은 사실상 평균선 바로 아래 자리한다 — 그러니 verdict 가 모드 (β, θ) 에 민감하다. 1 절 1.6 의 Wallet 4 가 그 사례.

### 4.9.6 한 iter 의 동형 부분 — Phase 5 의 BSGS

위 멱법 반복은 모두 평문이지만, 코드의 Phase 5 는 같은 결과를 동형으로 만들어낸다. 한 iter 의 동형 부분만 짧게 요약한다.

- cipherV (encode + encrypt 된 logicalV): 슬롯에 `[V[0], V[1], V[2], 0, V[0], V[1], V[2], 0]` 식의 패턴 (`prBlockSize = 2·nSub = 6` 슬롯이지만 본 예제는 nSub = 3, slot_count = 6 단순화 가정).
- m₁ = m₂ = 2 (`FindOptimalAsymmetricBSGS(3, 1.0)` 의 반환). 그러면 d ∈ {0, 1, 2} 가 (j, i) ∈ {(0,0), (0,1), (1,0)} 으로 쪼개진다. d = 3 은 nSub 를 넘어 인코딩 자체가 건너뛰어진다.
- 각 (j, i) 의 평문은 T 의 d = j·m₁ + i 번째 대각선을 `slot_idx = (row + j·m₁) mod nSub` 로 인코딩.
- baby_steps[0], [1] 사전 계산, j = 0..1 에 대해 평문 곱 + rescale + 누적, j = 1 의 결과를 m₁ = 2 슬롯 회전 후 합산.

세부 슬롯 트레이스는 3 절 3.9 와 *같은 패턴* 이라 생략한다 — 입력이 one-hot 이 아니라 일반 V 벡터라는 점만 다르고, 결과 ciphertext 의 앞 nSub 슬롯에 정확히 `T · V` 가 들어있다.

결과를 decrypt 한 다음 `max(0.0, val)` 으로 음수 clip → sum-to-1 정규화 → 다음 iter 의 `logicalV` 로. 매 iter 끝의 이 *decrypt + clip + 정규화 + re-encrypt* 가 4.5 에서 다룬 단일-당사자 가정의 결과다.
