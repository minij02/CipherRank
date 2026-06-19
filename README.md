# CipherRank

CipherRank는 신뢰 등급이 매겨진 거래 그래프 위에서 특정 지갑의 "신용도"를 PageRank로 평가하되, 서버에게는 어떤 지갑을 평가하는지조차 알리지 않는 파이프라인이다. CKKS 동형암호 위에 Halevi-Shoup 식 PIR을 얹어 행렬을 회전·곱해 부분 그래프를 추출하고, 그 위에서 멱법 반복으로 PageRank를 계산한다. 클라이언트는 마지막에 자기 점수 하나만 복호한다.

이 저장소는 그 파이프라인의 베이스라인과 두 가지 독립 최적화 (A1: 비대칭 BSGS + OpenMP, A2: 희소 2-hop 누적 + 의미 변경), 그리고 두 최적화를 결합한 통합 버전 B의 실측까지 담고 있다.

## 알고리즘 문서

전체 동작 원리와 단계별 실제 값의 흐름은 다음 문서들에 정리해 두었다. 빌드·실행만 보려면 아래의 "빌드와 실행" 절로 바로 가도 무방하다.

| 문서 | 내용 |
|---|---|
| `docs/algorithm/01-개요.md` | 데이터, 표기, 위협 모델, 6단계 흐름의 큰 그림 |
| `docs/algorithm/02-phase1-그래프-전처리.md` | BitcoinOTC 로딩, 시간 감쇠, top-N 빈도 컷, 1-hop·2-hop 누적, 대각선 평문 캐싱 |
| `docs/algorithm/03-phase3-bsgs-pir.md` | One-hot 인코딩, Halevi-Shoup 대각선 방식, 비대칭 BSGS의 수식과 비용 |
| `docs/algorithm/04-phase5-동형-pagerank.md` | 부분 그래프 정규화, α=0.85 텔레포테이션, 동형 멱법 반복 10회, 복호·재암호 우회 |
| `docs/algorithm/05-결과분석.md` | MVB 단발 측정, 모드별 wall-clock, OpenMP 스케일링, β·θ sweep, sybil 검출, FHE vs 평문 정밀도 |
| `docs/algorithm/06-엣지케이스와-구현-주의.md` | 필터의 사각지대, 청크 경계와 Q7 패딩, C8 보조정리, β₂=0 SEAL 예외, 키 스텝셋, 측정의 함정 |

## 빌드와 실행

Microsoft SEAL 4.1.2, CMake 3.10 이상, OpenMP가 필요하다. macOS는 Homebrew의 libomp로 충분하다.

```bash
mkdir -p build && cd build
cmake .. && cmake --build .
```

기본값으로 한 번 실행해 보려면:

```bash
./CipherRank -g 256 -s 64
```

다중 청크가 발생하는 큰 설정은 다음과 같이 실행한다.

```bash
./CipherRank -g 1024 -s 256 -b1 1.0 -b2 0.30 -thr 0.05 \
    1 2 4 35 25 7 88 100 200
```

명령행 옵션은 아래와 같다.

| 옵션 | 의미 | 기본값 |
|---|---|---|
| `-g <N>` | nGlobal, 빈도 기준 상위 N개 지갑으로 제한 | 256 |
| `-s <n>` | nSub, 부분 그래프 차원 | 64 |
| `-b1 <f>` | β₁, 1-hop 가중치 | 1.0 |
| `-b2 <f>` | β₂, 2-hop 가중치 | 0.30 |
| `-thr <f>` | 약한 1-hop 간선의 가지치기 임계값 | 0.05 |
| `-csv <path>` | 데이터셋 경로 변경 | `../soc-sign-bitcoinotc.csv` |
| 위치 인자 | 평가 대상 지갑 ID | `1 2 4 35` |

main과 알고리즘 수준에서 동치인 모드(R1''에서 사용)는 β₁=β₂=1, thr=0이다.

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
| B (이 브랜치) | 6.7s, 콜드 약 3.9s | 11.7×, 콜드 약 20× |
| nGlobal=4096 데모, B | 37s | main 실행 비현실적 |

R1''/R2''/R6''/R10'' 회귀 검증은 콜드 머신 조건에서 모두 통과했다. R8'' sybil regression은 자연 sybil 9+9와 합성 sybil 50개 두 세팅 모두에서 TPR 1.00이 나왔고, 가지치기를 끈 B-C2와 결과가 같았다. sparse 의미 변경이 sybil 탐지 능력을 깎아먹지는 않았다는 뜻이다.

세부 보고서는 다음 문서들에 정리되어 있다.

- `docs/superpowers/specs/2026-06-18-bgsg-strengthening-design.md` — A1 설계 v2
- `docs/superpowers/specs/2026-06-18-sparse-strengthening-design.md` — A2 설계 v2
- `docs/superpowers/specs/2026-06-18-integrated-bgsg-sparse-design.md` — B 통합 설계 v2
- `docs/superpowers/specs/2026-06-18-integrated-bgsg-sparse-phase-gamma-results.md` — MVB → 풀 통합
- `docs/superpowers/specs/2026-06-18-integrated-bgsg-sparse-sweep-results.md` — 샘플 sweep, 자연 sybil
- `docs/superpowers/specs/2026-06-18-integrated-bgsg-sparse-followup-results.md` — 합성 sybil, 미세 그리드, bootstrap CI, 열 부하

## 브랜치 구분

| 브랜치 | 내용 |
|---|---|
| `main` | 베이스라인 |
| `feat/sparse-twohop-precompute-experiment` | A2만 |
| `feat/bgsg-experiment` | A1만. v2 spec 세 편도 여기 보관 |
| `feat/bgsg-sparse-integrated` | B(이 브랜치). 통합 코드, sweep 인프라, 측정 보고서 |

## 재현용 스크립트

```bash
# nGlobal ∈ {256, 1024}, 4-way, N=3 반복
python3 scripts/sweep_runner.py --coarse --reps 3 \
    --out results/coarse_sweep.json

# 자연 sybil 9 + 신뢰 9
python3 scripts/sweep_runner.py --sybil --reps 1 \
    --out results/r8_sybil.json

# 합성 sybil 50개 주입 후 B vs B-C2
python3 scripts/gen_synthetic_sybil.py \
    --input soc-sign-bitcoinotc.csv \
    --output soc-sign-bitcoinotc-synthetic.csv --seed 1
python3 scripts/sweep_runner.py --synthetic-sybil --reps 1 \
    --csv ../soc-sign-bitcoinotc-synthetic.csv \
    --out results/r8_synthetic_sybil.json
```

`sweep_runner.py`는 네 브랜치의 빌드 경로를 직접 참조하므로, 여러 브랜치를 동시에 비교하려면 `git worktree`로 브랜치별 작업 디렉토리를 만들어 각각 빌드해두는 편이 깔끔하다.

## 라이선스

연구·학술 실험 용도. Microsoft SEAL은 Apache 2.0, BitcoinOTC 데이터셋은 Stanford SNAP 컬렉션의 라이선스를 따른다.
