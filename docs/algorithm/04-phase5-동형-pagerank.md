# 4. 부분 그래프 해상도와 동형 PageRank

Phase 4 와 Phase 5 는 평가 대상의 trust 분포로부터 *어떤 노드를 부분 그래프에 포함시킬 것인가* 를 결정하고, 그 부분 그래프 위에서 PageRank 의 멱법 반복을 수행하는 절차이다. Phase 6 은 최종 점수를 임계값과 비교하여 `APPROVED` 또는 `REJECTED` 의 판정을 산출한다. 본 장은 §4.1 에서 부분 그래프의 인덱스 결정을, §4.2 부터 §4.3 까지 부분 행렬의 구성과 column-stochastic 정규화를, §4.4 부터 §4.7 까지 멱법 반복의 평문 및 동형 구현을, §4.8 에서 최종 판정을 다룬다. 부록 §4.A 는 §1.6 의 N = 4 예제 위에서 멱법 반복의 10 회 결과를 손 계산으로 정리한다.

## 4.1 부분 그래프 인덱스 결정

Phase 3 의 출력 ciphertext 를 복호하고 디코딩한 결과는 청크별 슬롯 분포이다. 청크 c 의 c′ 번째 슬롯 묶음 [c′ · 2N, c′ · 2N + N) 에는 그 자리의 평가 대상이 다른 N 개 노드 각각에게 받는 1+2-홉 누적 trust 분포가 인코딩되어 있다. Phase 4 는 이 분포의 상위 nSub 개를 부분 그래프의 노드로 선택한다 (`CipherRank.cpp:613–652`).

```cpp
for (size_t c = 0; c < (end_idx - start_idx); c++) {
    vector<Score> scores;
    for (int i = 0; i < nGlobal; i++) {
        double val = decodedNeighbors[c * pirBlockSize + i];
        val = round(val * 100000.0) / 100000.0;
        scores.push_back({i, val});
    }
    sort(scores.begin(), scores.end(), [](const Score& a, const Score& b) {
        if (abs(a.score - b.score) < 1e-6) return a.index < b.index;
        return a.score > b.score;
    });
    vector<int> topNodes;
    for (int i = 0; i < nSub; i++) topNodes.push_back(scores[i].index);

    int targetGIdx = targetGlobalIndices[start_idx + c];
    if (find(topNodes.begin(), topNodes.end(), targetGIdx) == topNodes.end())
        topNodes[nSub - 1] = targetGIdx;
    // ...
}
```

본 절차에서 짚어둘 세 가지 처리는 다음과 같다.

**양자화.** CKKS 복호 결과는 평문 정답에 약 2⁻³⁵ 수준의 노이즈가 부가된 부동소수점이다. nSub 와 nSub + 1 위치에 들어갈 두 노드의 점수가 거의 같을 때 노이즈가 정렬 결과를 흔들 가능성이 있으므로, `round(val · 10⁵) / 10⁵` 양자화와 1e-6 의 tie-break 기준을 통해 결정적 정렬을 보장한다.

**평가 대상의 강제 포함.** 평가 대상이 자기 자신의 top-nSub 에 포함되지 못한 경우 마지막 슬롯에 강제로 삽입한다. PageRank 가 부분 그래프 내 평가 대상의 점수를 산출해야 하므로, 평가 대상이 부분 그래프에 *반드시* 포함되도록 보장하는 안전장치이다.

**평문 출력.** topNodes 와 평가 대상의 부분 그래프 내 인덱스 subIdx 는 평문으로 출력된다. 이는 §1.5 의 위협 모델에 부합하며, 부분 그래프의 *구조* 는 서버에 노출되지만 평가 결과 점수 자체는 끝까지 ciphertext 내부에 머문다.

## 4.2 부분 행렬 추출과 column-stochastic 정규화

Phase 5 의 첫 번째 단계는 평가 대상별 부분 행렬 `M_sub` 의 구성이다 (`CipherRank.cpp:668–682`).

```cpp
for (size_t c = 0; c < num_targets; c++) {
    for (int i = 0; i < nSub; i++) {
        for (int j = 0; j < nSub; j++)
            all_M_sub[c][i][j] = SparseGet(M_pub, allTopNodes[c][i], allTopNodes[c][j]);
    }
    // column 정규화 + teleport ...
}
```

Q5 의 도입에 따라 `M_pub` 이 희소 표현으로 유지되므로, 부분 행렬 추출은 `operator[]` 가 아닌 const-safe 한 `SparseGet` 을 사용한다. `operator[]` 를 사용하는 경우 미존재 키에 대해 0 값이 자동 *삽입* 되어 const-safety 가 깨지고 메모리도 부풀어 오른다 (자세한 논의는 §5.5 의 Q5 항목).

부분 행렬이 구성되면 column-stochastic 정규화가 적용된다. PageRank 의 transition matrix 는 각 열의 합이 1 이 되도록 정규화되어야 하며, 본 시스템은 다음 절차를 따른다.

```cpp
double alpha = 0.85, tele = (1.0 - alpha) / nSub;
for (int j = 0; j < nSub; j++) {
    double colSum = 0.0;
    for (int i = 0; i < nSub; i++) colSum += all_M_sub[c][i][j];
    if (colSum == 0.0) all_M_sub[c][j][j] = 1.0;
    else for (int i = 0; i < nSub; i++) all_M_sub[c][i][j] /= colSum;
    for (int i = 0; i < nSub; i++)
        all_M_sub[c][i][j] = (alpha * all_M_sub[c][i][j]) + tele;
}
```

PageRank 의 transition 은 *1-홉* 행렬 `M_pub` 위에서 정의되며, top-nSub 의 결정만 1+2-홉의 `M_total` 을 사용한다는 점에 주목한다. 이 비대칭은 의도된 설계 선택이며, "부분 그래프 선택은 넓은 영향력 (확장된 이웃) 으로 평가하되, PageRank 의 random walk 자체는 직접 신뢰만으로 정의한다" 는 의미 모델을 반영한다.

## 4.3 텔레포트와 dangling 노드 처리

α = 0.85 의 damping factor 와 균일 텔레포트는 PageRank 의 표준 형식을 따른다. transition 의 최종 형태는

$$T[i][j] = \alpha \cdot \widehat{M}_{\mathrm{sub}}[i][j] + \frac{1 - \alpha}{n_{\mathrm{sub}}} \tag{4.1}$$

로 표현되며, 여기서 $\widehat{M}_{\mathrm{sub}}$ 는 열 정규화된 부분 행렬이다.

**Dangling 노드의 처리.** colSum = 0 인 열, 즉 부분 그래프 내에 outflow 가 전혀 없는 노드 j 에 대해 본 시스템은 `M_sub[j][j] = 1.0` 으로 두어 random walk 가 자기 자신에 머무는 분포로 정의한다. 이는 Stanford PageRank 의 원 논문 (Page et al., 1999) 이 제시하는 표준적 처리이며, dangling 노드의 행이 모두 0 인 상태에서 column-stochastic 성질이 깨지는 것을 방지한다.

α = 0.85 의 선택은 PageRank 의 관례적 기본값으로, 너무 큰 α 는 그래프 구조의 자기 반복 효과를 증폭시키고 너무 작은 α 는 그래프 정보를 사실상 무시하여 균일 분포에 수렴시킨다. 본 보고서의 범위 내에서는 α 의 변화에 대한 민감도 분석을 수행하지 않으며, 후속 작업으로 분리한다.

## 4.4 평문 멱법 반복 — 검증 기준선

본 시스템은 동형 멱법 반복에 앞서 동일 부분 행렬에 대한 평문 멱법 반복을 수행한다 (`CipherRank.cpp:684–693`). 이는 두 가지 목적을 가진다.

(i) Phase 6 의 정밀도 지표 (Precision Error = |fheScore − groundTruthScore|) 를 산출하기 위한 ground truth 의 확보.

(ii) 동일 부분 그래프에 대한 평문과 동형 결과의 일치 여부를 통해 CKKS 노이즈 누적의 영향을 정량화.

평문 멱법은 초기 벡터 $V_0 = (1/n_{\mathrm{sub}}, \ldots, 1/n_{\mathrm{sub}})$ 로부터 $V_{t+1} = T \cdot V_t$ 를 10 회 반복하여 $V_{10}$ 을 산출한다. 부분 그래프가 동일하다면 평문과 동형의 결과가 일치해야 한다는 가정 자체가 §5 의 R1 / R2 / R6 검증의 출발점이다.

## 4.5 동형 멱법 반복과 복호-재암호화 루프

Phase 5 의 동형 부분은 청크 루프 안에서 다음 5 단계를 ITER = 10 회 반복한다 (`CipherRank.cpp:728–836`).

1. 현재 logical V (평문) 를 CKKS 로 인코딩하고 암호화한다.
2. m₁ − 1 회의 회전으로 baby step 사전 계산을 수행한다.
3. j = 0, …, m₂ − 1 에 대해 BsgsDiag 와의 평문 곱과 rescale, mod_switch, 누적, 그리고 j · m₁ 회전과 전체 합산을 수행한다.
4. 결과 ciphertext 를 복호하고 디코딩하여 평문 벡터를 얻는다.
5. 음수 슬롯을 0 으로 절단 (clip) 하고, 합이 0 이 아닌 경우 sum-to-1 로 재정규화한다. 그 결과를 다음 반복의 입력으로 사용한다.

수식으로 표현하면 한 반복은 다음과 같다.

$$y = T \cdot V \quad \text{(CKKS 위에서 BSGS 로 동형 계산)} \tag{4.2}$$

$$V_{\mathrm{new}} = \mathrm{clip}(\mathrm{decrypt}(y), 0) \,/\, \textstyle\sum_i \mathrm{clip}(\cdot)_i \tag{4.3}$$

평문 멱법과 등가인 구간은 1–3 단계이며, 단순화가 도입된 부분은 4–5 단계이다. 매 반복의 *끝* 에서 평문으로 복호되고 *시작* 에서 다시 암호화되는 이 루프를 본 보고서에서는 *decrypt–reencrypt loop* 로 부른다.

**왜 매 반복마다 복호 및 재암호화인가.** 본 시스템의 CKKS 파라미터 (`CipherRank.cpp:289`)

```cpp
parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 45, 45, 60 }));
```

는 useful multiplicative depth 가 약 2 이다. 10 회 반복의 동형 곱을 ciphertext 만으로 지속하려면 약 10 단계의 depth 가 요구되며, 이는 SEAL CKKS 4.1.2 가 지원하지 않는 bootstrapping 없이는 불가능하다.

복호 후 재암호화는 CKKS 노이즈를 0 으로 초기화하고 ciphertext 의 useful depth 를 완전히 회복시킨다. 그러나 이 단순화는 서버가 비밀키를 소유해야 함을 함의하므로, §1.5 에서 명시한 단일 당사자 측정 가정의 직접적 원인이 된다. 진정한 PIR 위협 모델로의 확장 경로는 §5.7 의 후속 항목에서 다룬다.

## 4.6 Phase 5 의 BSGS — Phase 3 와의 차이

Phase 5 의 BSGS 는 차원이 N 이 아닌 n = nSub 인 점을 제외하면 Phase 3 와 동일한 구조를 갖는다. 본 시스템의 기본값 nSub = 64 에 대해 `FindOptimalAsymmetricBSGS(64, 1.0)` 는 m₁ = m₂ = 8 을 반환하며 (Q1 적용 후 16, 16 으로 조정될 수도 있으나 본 절에서는 표준 값으로 8 을 사용), 회전 총합은 약 14 회이다.

`BsgsDiag` 의 인코딩 자체는 매 청크마다 새로 수행된다 (`CipherRank.cpp:741–764`). Phase 1 의 BsgsDiag 가 전역 N 차원 행렬에 대해 한 번만 구성되는 것과 달리, 부분 행렬은 청크별로 다르므로 그 nSub 개 대각선을 매번 인코딩해야 한다.

`if (val > 0.0) isZero = false;` 의 영-스킵 가드는 그대로 유지된다. 부분 그래프의 한 대각선이 완전히 0 인 경우 해당 d 의 BsgsDiag 가 생성되지 않으며, 이는 평문 곱과 덧셈의 횟수에 데이터 의존성을 도입한다. 부분 그래프가 평가 대상의 함수이므로 wall-clock 이 평가 대상별로 미세하게 달라질 수 있으나, 본 보고서의 단일 당사자 측정 가정에서는 이 점이 보안상 의미를 갖지 않는다.

## 4.7 매 반복 후의 clip 과 재정규화

복호된 평문 벡터에 대한 최종 처리는 다음 두 단계로 구성된다 (`CipherRank.cpp:823–835`).

```cpp
double sum = 0.0;
for (int i = 0; i < nSub; i++) {
    double val = max(0.0, decoded[c * prBlockSize + i]);
    logicalV[start_idx + c][i] = val;
    sum += val;
}
if (sum == 0.0)
    for (int i = 0; i < nSub; i++) logicalV[start_idx + c][i] = 1.0 / nSub;
else
    for (int i = 0; i < nSub; i++) logicalV[start_idx + c][i] /= sum;
```

**음수 절단.** PageRank 의 확률 분포는 비음수여야 하나, CKKS 노이즈로 인해 0 근처의 값이 음수로 떨어질 수 있다. `max(0.0, val)` 의 절단이 이를 보정한다.

**재정규화.** 평문 멱법에서는 column-stochastic 한 transition 행렬과 sum-to-1 인 입력 벡터로부터 sum-to-1 인 출력 벡터가 자동으로 보장되지만, 동형 위의 노이즈 누적과 column 정규화의 미세 오차로 인해 합이 정확히 1 이 아닐 수 있다. 이 처리는 매 반복 후 확률 분포의 성질을 명시적으로 회복시키는 안전장치이다.

sum 이 0 인 극단적 경우 균일 분포로의 리셋이 적용되는데, 이는 모든 슬롯이 노이즈로 인해 음수가 된 비정상 상황에 대한 fallback 이다.

## 4.8 최종 판정

10 회 반복 후의 `logicalV[c][allTargetSubIdx[c]]` 가 평가 대상 c 의 FHE 측 점수 (fheScore) 이며, 평문 측 `all_plainV[c][allTargetSubIdx[c]]` 가 ground truth 이다. 양자의 차이가 Precision Error 로 보고된다.

판정 자체는 단순한 임계값 비교이다 (`CipherRank.cpp:826`).

```cpp
if (fheScore >= 0.0150) cout << "[APPROVED] Minimum threshold met.";
else cout << "[REJECTED] Insufficient trust score.";
```

임계값 0.0150 은 코드 내에 하드코딩되어 있으며, 그 통계적 정당화는 본 보고서의 범위에 포함되지 않는다. nSub = 64 의 경우 균일 분포 점수가 1 / 64 ≈ 0.0156 이므로, 본 임계값은 사실상 평균선 직하에 위치한다. nSub = 256 의 경우 균일 점수가 0.0039 로 떨어지므로 동일 임계값이 평균의 약 4 배 위에 위치하게 된다. 즉 임계값의 *의미* 는 nSub 에 강하게 의존하며, 후속 작업에서는 이를 nSub 의 함수로 파라미터화하는 것이 바람직하다.

baseline 과 통합 B 의 판정이 동일 입력에서 다르게 나오는 사례 (예: §1 의 Wallet 4) 는 BSGS 의 노이즈가 아닌 β · θ 의 의미 모델 변경에서 유래한다. 의미 모델이 변경되면 Phase 3 가 다른 trust 분포를 산출하고, Phase 4 의 top-nSub 가 달라지며, 결과적으로 Phase 5 의 부분 행렬과 그 위의 PageRank 가 모두 달라진다.

---

## 부록 4.A — N = 4 예제에 대한 동형 PageRank 의 손 계산

§3.A 의 끝에서 얻은 PIR 결과 `[5.8, 3.6, 4.8, 2.0]` 을 입력으로 하여, 부분 그래프 구성부터 verdict 산출까지의 절차를 손 계산으로 추적한다. 그래프의 작은 크기를 고려하여 nSub = 3 으로 둔다.

### 4.A.1 양자화와 top-3 결정

복호 결과 vector 의 앞 4 슬롯 `[5.8, 3.6, 4.8, 2.0]` 에 1e-5 양자화를 적용해도 값이 정수 + 한 자리 소수이므로 변화가 없다. (idx, score) 쌍을 점수 기준 내림차순으로 정렬하면

$$[(0, 5.8), (2, 4.8), (1, 3.6), (3, 2.0)]$$

이며, 상위 3 개는 `topNodes = [0, 2, 1]` 이다. 평가 대상 wallet 30 의 globalIdx = 1 이 topNodes 에 포함되어 있으며, 그 부분 그래프 내 위치는 subIdx = 2 이다.

### 4.A.2 부분 행렬

`M_sub[i][j] = M_pub[topNodes[i]][topNodes[j]]` 로부터 9 개 성분을 추출한다.

| | j=0 (idx 0) | j=1 (idx 2) | j=2 (idx 1) |
|---|---:|---:|---:|
| i=0 (idx 0) | 0 | 0 | 4 |
| i=1 (idx 2) | 4 | 0 | 0 |
| i=2 (idx 1) | 3 | 5 | 0 |

행렬 표기:

$$M_{\mathrm{sub}} = \begin{pmatrix} 0 & 0 & 4 \\ 4 & 0 & 0 \\ 3 & 5 & 0 \end{pmatrix}.$$

### 4.A.3 정규화와 텔레포트

각 열의 합과 정규화 결과는 다음과 같다.

- col 0 의 합 = 7. 정규화 후 [0, 4/7, 3/7] ≈ [0, 0.5714, 0.4286]
- col 1 의 합 = 5. 정규화 후 [0, 0, 1]
- col 2 의 합 = 4. 정규화 후 [1, 0, 0]

dangling 노드는 존재하지 않는다. α = 0.85, tele = 0.05 를 식 (4.1) 에 적용한 transition matrix T 는

$$T \approx \begin{pmatrix} 0.0500 & 0.0500 & 0.9000 \\ 0.5357 & 0.0500 & 0.0500 \\ 0.4143 & 0.9000 & 0.0500 \end{pmatrix}.$$

각 열의 합 검증: 0.05 + 0.5357 + 0.4143 = 1.0000, 0.05 + 0.05 + 0.9 = 1.0, 0.9 + 0.05 + 0.05 = 1.0. column-stochastic 성질이 보존된다.

### 4.A.4 멱법 반복

초기 $V_0 = [1/3, 1/3, 1/3] \approx [0.3333, 0.3333, 0.3333]$ 로부터 $V_{t+1} = T \cdot V_t$ 의 반복을 적용한 결과는 다음 표와 같다 (소수점 4 자리 반올림).

| t | V[0] | V[1] | V[2] | 합 |
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

합의 마지막 자리에서 발생하는 ±0.0001 의 오차는 각 반복의 중간 결과를 4 자리 반올림한 데서 누적되는 양이며, 실제 코드에서는 매 반복 후의 sum-to-1 재정규화 (§4.7) 가 이를 다시 정확히 1 로 보정한다.

본 예제의 nSub = 3 이라는 작은 차원에서는 1 자리 진동이 10 회 반복 이후에도 잔존한다. 실제 BitcoinOTC 의 nSub = 64 / 256 환경에서는 약 5 회 반복으로 10⁻⁴ 자리의 수렴이 관측된다.

### 4.A.5 점수와 판정

평가 대상의 subIdx = 2 이므로 fheScore = $V_{10}[2] \approx 0.3865$ 이다. 임계값 0.0150 과 비교하면

$$0.3865 \geq 0.0150 \implies \texttt{[APPROVED] Minimum threshold met.}$$

본 예제에서 점수가 임계값을 큰 폭으로 상회하는 것은 nSub = 3 이라는 비현실적으로 작은 부분 그래프에서 wallet 30 이 다른 두 노드 (wallet 10, wallet 20) 로부터 직접적 신뢰를 모두 받기 때문이다. 실제 BitcoinOTC 의 nSub = 64 환경에서는 균일 분포 점수가 1/64 ≈ 0.0156 으로 임계값 직상에 위치하며, 따라서 판정이 의미 모델 (β, θ) 의 미세한 변화에 민감하게 반응한다.

### 4.A.6 한 반복의 동형 부분

위 멱법 반복은 모두 평문 연산으로 기술하였으나, Phase 5 의 코드는 동일한 결과를 동형으로 산출한다. 한 반복의 동형 부분은 다음의 흐름을 따른다.

(i) cipherV 의 슬롯에 `[V[0], V[1], V[2], 0, V[0], V[1], V[2], 0]` 패턴의 평문이 인코딩되고 (`prBlockSize = 2 · nSub = 6` 의 가정 하에), 암호화된다.

(ii) `FindOptimalAsymmetricBSGS(3, 1.0)` 가 m₁ = m₂ = 2 를 반환한다. d ∈ {0, 1, 2} 가 (j, i) ∈ {(0, 0), (0, 1), (1, 0)} 으로 분해된다. d = 3 은 nSub 를 초과하므로 인코딩되지 않는다.

(iii) 각 (j, i) 의 BsgsDiag 평문은 T 의 d 번째 대각선을 `slot_idx = (row + j · m₁) mod n_sub` 위치에 인코딩한다.

(iv) baby_steps[0], baby_steps[1] 의 사전 계산 후, j = 0 부터 1 까지의 평문 곱과 rescale, 누적, 그리고 j = 1 의 결과를 m₁ = 2 슬롯 회전 후 합산한다.

(v) 결과 ciphertext 의 앞 3 슬롯에 $T \cdot V$ 가 인코딩되어 있다. 이를 복호하고 §4.7 의 절단과 재정규화를 적용하면 다음 반복의 logicalV 가 산출된다.

세부 슬롯 단위 트레이스는 §3.A 와 동일한 구조이므로 본 부록에서는 생략한다. 입력이 one-hot 이 아닌 일반적 확률 벡터라는 점만 다르며, 결과 ciphertext 의 앞 nSub 슬롯이 $T \cdot V$ 와 정확히 일치한다는 결론은 보조정리 3.1 의 직접적 귀결이다.
