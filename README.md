# CipherRank

비트코인 OTC 거래 그래프에서 특정 지갑의 신뢰도를 평가하는 sybil 방어 파이프라인이다. 서버는 어떤 지갑이 평가 대상인지 모른 채로, CKKS 기반 동형암호와 PIR을 결합해 PageRank 기반 점수를 산출한다. 클라이언트는 마지막에 자신의 점수 하나만 복호해서 받는다.

## 파이프라인

전체는 여섯 단계로 나뉜다.

Phase 1에서 서버가 SNAP의 BitcoinOTC 데이터셋을 읽어 시간 감쇠를 적용한 거래 그래프를 만들고, PIR에 쓸 대각선 평문 데이터를 캐싱한다. Phase 2에서 클라이언트가 평가 대상 지갑들의 인덱스를 one-hot 벡터로 묶어 SIMD로 암호화해 보낸다. Phase 3에서 서버는 평가 대상이 누구인지 모른 채 동형 행렬-벡터 곱을 통해 이웃 가중치를 뽑아낸다. Phase 4에서 클라이언트가 결과를 복호해 서브그래프 핵심 노드 nSub개를 고르고, Phase 5에서 이 작은 서브그래프 위에서 동형 PageRank를 10회 돌린다. 마지막 Phase 6은 점수가 임계값 0.0150 이상인지로 승인/거부를 결정한다.

## 디렉토리 구성

```
CipherRank.cpp              통합 파이프라인 (약 930줄)
CMakeLists.txt              SEAL 4.1.2 + OpenMP 빌드
soc-sign-bitcoinotc.csv     SNAP 데이터셋 (35,592행)
soc-sign-bitcoinotc-synthetic.csv  합성 sybil 50개를 덧붙인 버전
scripts/
  sweep_runner.py           4-way 측정 러너
  gen_synthetic_sybil.py    합성 sybil 생성기 (seed=1)
results/*.json              raw 측정 데이터
docs/superpowers/specs/     설계 문서와 측정 보고서
```

## 빌드와 실행

Microsoft SEAL 4.1.2, CMake 3.10 이상, OpenMP가 있어야 한다. macOS는 Homebrew로 libomp를 깔아두면 충분하다.

```bash
mkdir -p build && cd build
cmake .. && cmake --build .
```

기본 파라미터로 한 번 돌려보려면 다음과 같이 한다.

```bash
./CipherRank -g 256 -s 64
```

좀 더 큰 다중 청크 케이스는 이렇게 실행한다.

```bash
./CipherRank -g 1024 -s 256 -b1 1.0 -b2 0.30 -thr 0.05 \
    1 2 4 35 25 7 88 100 200
```

명령행 옵션은 다음과 같다.

| 옵션 | 의미 | 기본값 |
|---|---|---|
| `-g <N>` | nGlobal — 빈도 기준 상위 N개 지갑으로 제한 | 256 |
| `-s <n>` | nSub — 서브그래프 차원 | 64 |
| `-b1 <f>` | β₁, 1-hop 가중치 | 1.0 |
| `-b2 <f>` | β₂, 2-hop 가중치 | 0.30 |
| `-thr <f>` | 약한 1-hop 간선을 잘라낼 임계값 | 0.05 |
| `-csv <path>` | 데이터셋 경로 변경 | `../soc-sign-bitcoinotc.csv` |
| 위치 인자 | 평가 대상 지갑 ID | `1 2 4 35` |

main 브랜치와 같은 의미 모델로 돌려서 알고리즘 동등성(R1'')을 확인하려면 β₁=β₂=1, thr=0으로 주면 된다.

```bash
./CipherRank -g 1024 -s 256 -b1 1.0 -b2 1.0 -thr 0 \
    1 2 4 35 25 7 88 100 200
```

## 측정 결과 요약

Config B(nGlobal=1024, 9개 타겟, 청크 5개, OMP=4) 기준이다. 단일 Apple Silicon 머신에서 측정했다.

| 모드 | 총 wall-clock | main 대비 |
|---|---:|---:|
| main | 78.2s | 1.00× |
| A1 (bgsg + H-2) | 11.3s | 6.9× |
| A2 (sparse 단독) | 73.2s | 1.07× |
| B (이 브랜치) | 6.7s (콜드 약 3.9s) | 11.7× (콜드 약 20×) |
| nGlobal=4096 데모 (B) | 37s | main은 실행 비현실적 |

R1'' / R2'' / R6'' / R10'' 회귀 검증은 콜드 머신 조건에서 모두 통과했다. R8'' sybil regression은 자연 sybil 9+9와 합성 sybil 50개 두 세팅 모두에서 TPR 1.00이 나왔고, 가지치기를 끈 B-C2와 결과가 같았다. 결국 sparse 의미 모델 변경이 sybil 탐지 능력을 떨어뜨리진 않았다는 뜻이다.

세부 측정과 논의는 다음 문서에 흩어져 있다.

- `2026-06-18-bgsg-strengthening-design.md` — A1 설계 v2 (BSGS + OMP + H-2)
- `2026-06-18-sparse-strengthening-design.md` — A2 설계 v2 (sparse Phase 1 + β-가중 hop)
- `2026-06-18-integrated-bgsg-sparse-design.md` — B 통합 설계 v2
- `2026-06-18-integrated-bgsg-sparse-phase-gamma-results.md` — MVB에서 풀 통합까지
- `2026-06-18-integrated-bgsg-sparse-sweep-results.md` — 샘플 sweep, 자연 sybil 결과
- `2026-06-18-integrated-bgsg-sparse-followup-results.md` — 합성 sybil, 미세 그리드, bootstrap CI, 열 부하 관찰

## 브랜치 구분

| 브랜치 | 내용 |
|---|---|
| `main` | 베이스라인 파이프라인 |
| `feat/sparse-twohop-precompute-experiment` | A2만: Phase 1 sparse + β·threshold |
| `feat/bgsg-experiment` | A1만: 비대칭 BSGS + OMP + Phase 5 thread-local. v2 spec 세 편도 여기에 보관 |
| `feat/bgsg-sparse-integrated` | B (현재 브랜치). 통합 코드, sweep 인프라, 측정 보고서 |

## Sweep 재현

```bash
# nGlobal ∈ {256, 1024}, 4-way, N=3 반복
python3 scripts/sweep_runner.py --coarse --reps 3 \
    --out results/coarse_sweep.json

# 자연 sybil 9 + 신뢰 9
python3 scripts/sweep_runner.py --sybil --reps 1 \
    --out results/r8_sybil.json

# 합성 sybil 50 (B와 B-C2만 비교)
python3 scripts/gen_synthetic_sybil.py \
    --input soc-sign-bitcoinotc.csv \
    --output soc-sign-bitcoinotc-synthetic.csv --seed 1
python3 scripts/sweep_runner.py --synthetic-sybil --reps 1 \
    --csv ../soc-sign-bitcoinotc-synthetic.csv \
    --out results/r8_synthetic_sybil.json
```

`sweep_runner.py`는 네 브랜치의 빌드 경로를 직접 참조하기 때문에, 여러 브랜치를 같이 비교하려면 `git worktree add`로 브랜치별 작업 디렉토리를 만들어 각각 빌드해두는 게 가장 깔끔하다.

## 알려진 한계

측정은 한 대의 머신에서만 진행했다. 긴 sweep을 연달아 돌리면 발열과 메모리 압박 때문에 wall-clock이 25~40% 늘어나는 현상이 반복적으로 나왔다. 자세한 양상은 followup-results 문서 4절에 정리해 두었고, 캐노니컬한 R10'' 측정값은 spec 6.5절의 권고대로 측정 사이에 60초씩 비워둔 조건에서 얻은 값이다.

Sybil 검증에 쓴 표본 크기가 작다는 점도 함께 짚어둘 필요가 있다. 자연 sybil은 BitcoinOTC에서 음수 평균 평점을 가진 노드 9개 + 신뢰 노드 9개, 합성 sybil은 한 종류의 mutual ring 50개뿐이다. 트러스트 허브와 일부 연결을 가진 sybil 프로파일이나 다른 데이터셋으로의 일반화는 후속 작업으로 남겨두었다.

B 파이프라인의 Phase 5에는 weight 자동 튜닝 측정이 여전히 들어 있다. 다만 측정값으로 도출한 (m1, m2)는 실제로 사용되지 않는다 — Galois 키가 초기화 시점에 weight=1.0 가정으로 이미 고정되기 때문이다. spec의 B0 풀 Three-Pass는 부분 구현 상태로 남아 있다.

β₂=0으로 두면 SEAL이 "transparent ciphertext" 예외를 던지는 버그가 있었는데, Phase 1 reduce 단계에서 값이 0인 항목을 미리 거르도록 고쳐 해결했다. 경위는 followup-results 2a절에 적어 두었다.

## 라이선스

연구·학술 실험 용도. Microsoft SEAL은 Apache 2.0, BitcoinOTC 데이터셋은 Stanford SNAP 컬렉션의 라이선스를 따른다.
