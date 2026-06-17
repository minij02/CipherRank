/// <summary>
/// file: CipherRank.cpp
/// description: 동형암호와 PIR(비공개 정보 검색)을 결합하여
/// 네트워크 내 특정 타겟 지갑의 신뢰도를 평가하는 시빌 방어 파이프라인입니다.
/// </summary>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <map>
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <iomanip>
#include <omp.h>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// [Q5] M_pub 을 sparse 표현 (행 단위 hash) 으로 저장. dense N×N 대신 nnz·~48 bytes.
// nGlobal=4096 에서 128 MB → ~150 KB. 4096 demo 의 메모리 enabler.
using SparseMatrix = vector<unordered_map<int, double>>;

inline double SparseGet(const SparseMatrix& M, int i, int j) {
    if (i < 0 || i >= static_cast<int>(M.size())) return 0.0;
    auto it = M[i].find(j);
    return (it != M[i].end()) ? it->second : 0.0;
}

/// <summary>
/// 그래프의 간선(Edge) 정보를 표현하는 구조체입니다.
/// </summary>
struct Edge {
    /// <summary>송신자(Source) 지갑의 고유 ID입니다.</summary>
    int src;
    
    /// <summary>수신자(Target) 지갑의 고유 ID입니다.</summary>
    int tgt;
    
    /// <summary>거래의 가중치(신뢰도 또는 거래 횟수/금액 등)입니다.</summary>
    int weight;
    
    /// <summary>거래가 발생한 시점의 유닉스 타임스탬프입니다. 시계열 감쇠 계산에 사용됩니다.</summary>
    int time;
};

/// <summary>
/// 비대칭 BSGS(Baby-Step Giant-Step) 연산을 위해 사전 연산 및 캐싱된 대각선 평문 데이터를 표현하는 구조체입니다.
/// </summary>
/// <remarks>
/// Phase 1에서 역방향 시프트(Reverse Shift)가 적용된 상태로 인코딩되며, 
/// Phase 3 및 Phase 5의 Giant-Step 연산 시 Baby-Step 암호문과의 동형 곱셈에 매핑 데이터로 사용됩니다.
/// </remarks>
struct BsgsDiag { 
    /// <summary>Baby-Step 인덱스입니다 (0 ~ m1-1).</summary>
    int i; 

    /// <summary>Giant-Step 인덱스입니다 (0 ~ m2-1).</summary>
    int j; 

    /// <summary>역방향 시프트가 적용된 후 인코딩된 대각선 평문 데이터입니다.</summary>
    Plaintext plain; 
};

/// <summary>
/// BSGS 파라미터를 담을 구조체입니다.
/// </summary>
struct BSGSParams {
    /// <summary>Baby-Step 크기입니다.</summary>
    int m1;

    /// <summary>Giant-Step 크기입니다.</summary>
    int m2;
};

/// <summary>
/// N차원 서브그래프에 대해 최소 비용을 갖는 비대칭 BSGS 파라미터를 탐색합니다.
/// </summary>
/// <param name="N">목표 차원 (nSub, 예: 256, 1024)</param>
/// <param name="giant_weight">Baby Step 대비 Giant Step의 상대적 비용 가중치</param>
/// <returns>탐색된 최적의 m1(Baby Step)과 m2(Giant Step) 값을 포함하는 BSGSParams 구조체입니다.</returns>
/// <remarks>
/// 단순히 제곱근(sqrt)을 사용하는 대칭 BSGS의 한계를 극복하기 위해, 
/// 런타임 환경의 연산 프로파일링 결과를 가중치로 반영하는 Auto-Tuner 로직입니다.
/// </remarks>
BSGSParams FindOptimalAsymmetricBSGS(int N, double giant_weight = 2.0) {
    int best_m1 = 1;
    int best_m2 = N;
    double min_cost = 1e9; // 초기값 무한대

    // m1을 1부터 N까지 늘려가며 최적의 조합을 찾음
    for (int m1 = 1; m1 <= N; m1++) {
        int m2 = (N + m1 - 1) / m1; // N을 커버하기 위한 최소 m2

        // 비용(Cost) 함수 = (Baby Step 횟수) + 가중치 * (Giant Step 횟수)
        double cost = m1 + giant_weight * m2;

        if (cost < min_cost) {
            min_cost = cost;
            best_m1 = m1;
            best_m2 = m2;
        }
    }

    cout << " [Auto-Tune] N=" << N << " -> Optimal Asymmetric BSGS: "
         << "m1(Baby)=" << best_m1 << ", m2(Giant)=" << best_m2
         << " (Weight: " << giant_weight << "x)" << endl;

    return {best_m1, best_m2};
}

/// <summary>
/// (m1, m2) 쌍에 대해 BSGS rotation 에 실제로 필요한 step set 을 계산합니다.
/// P1 (Galois Key Slimming) 의 일부: 키 생성 비용을 O(N) → O(m1 + m2) 로 축소.
/// </summary>
static vector<int> ComputeBSGSStepSet(const BSGSParams& params, int N) {
    vector<int> steps;
    for (int i = 1; i < params.m1; i++) steps.push_back(i);          // baby steps
    for (int j = 1; j < params.m2; j++) {                            // giant steps
        int step = j * params.m1;
        if (step < N) steps.push_back(step);
    }
    return steps;
}

/// <summary>
/// 데이터 조작을 차단하기 위한 서버 측 전처리와, 
/// 타겟 익명성을 보장하는 클라이언트 측 블라인드 추출(PIR), 그리고 오차 검증을 총괄하는 코어 클래스입니다.
/// </summary>
/// <remarks>
/// - 메모리 단편화 방지: 모든 FHE 내부 연산은 동적 할당을 최소화하는 _inplace 계열 함수를 사용합니다.
/// - 멀티스레딩 제어: OpenMP를 통해 Phase 3 및 Phase 5의 Chunk 단위 병렬 처리를 수행합니다.
/// </remarks>
class UltimatePrivacyPipeline {
private:
    vector<int> requestedWalletIds;
    vector<int> validWalletIds;
    vector<int> targetGlobalIndices;

    int nGlobal;
    int pirInnerDim = nGlobal;
    int pirBlockSize = 2 * pirInnerDim;

    int nSub;
    int prInnerDim = nSub;
    int prBlockSize = 2 * prInnerDim;

    size_t poly_modulus_degree;

    // B1 (minimal): RunConfig 값. main() 에서 setter 로 주입.
    double beta1_ = 1.0;
    double beta2_ = 0.30;
    double prune_threshold_ = 0.05;

    // P1 (Galois Key Slimming): InitializeFHE 직전에 RunPipeline 에서 채워넣음.
    vector<int> galois_step_set_;

public:
    void SetConfig(double b1, double b2, double thr) {
        beta1_ = b1; beta2_ = b2; prune_threshold_ = thr;
    }

private:

    shared_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    GaloisKeys galois_keys;
    PublicKey public_key;
    SecretKey secret_key;
    
    size_t slot_count;
    double scale;
    size_t num_targets;
    int batch_size;
    int num_chunks;

public:
    /// <summary>
    /// 동적 파라미터와 병렬 처리할 타겟 지갑들의 ID 목록을 받아 파이프라인 인스턴스를 초기화합니다.
    /// </summary>
    /// <param name="walletIds">신용도를 검증할 타겟 지갑 ID들의 배열입니다.</param>
    UltimatePrivacyPipeline(const vector<int>& walletIds, int n_global, int n_sub, size_t poly_degree) {
        nGlobal = n_global;
        pirInnerDim = nGlobal;
        pirBlockSize = 2 * pirInnerDim;

        nSub = n_sub;
        prInnerDim = nSub;
        prBlockSize = 2 * prInnerDim;

        poly_modulus_degree = poly_degree;

        unordered_set<int> seen;
        for (int id : walletIds) {
            if (seen.insert(id).second) {
                requestedWalletIds.push_back(id);
            }
        }
    }

    /// <summary>
    /// 전체 시빌 방어 파이프라인을 순차적으로 실행하는 메인 엔트리 API입니다.
    /// </summary>
    void RunPipeline() {
        auto total_start = chrono::high_resolution_clock::now();

        // B0 (단순 형태): InitializeFHE 직전에 Phase 3 + Phase 5 의 step set 합집합을 계산.
        // FindOptimalAsymmetricBSGS 는 순수 함수이므로 FHE 컨텍스트 없이 호출 가능.
        // weight 측정 (auto-tune) 은 키 생성 후이므로 여기서는 default weight=1.0 사용 — 현 B-γ 범위.
        BSGSParams pirParams = FindOptimalAsymmetricBSGS(nGlobal, 1.0);
        BSGSParams prParams  = FindOptimalAsymmetricBSGS(nSub,    1.0);

        vector<int> stepsPir = ComputeBSGSStepSet(pirParams, nGlobal);
        vector<int> stepsPr  = ComputeBSGSStepSet(prParams,  nSub);

        // Union (정렬 + 중복 제거). 측정 dummy rotation (현 코드 line 603/609) 의 {1, 16} 포함.
        set<int> unionSet(stepsPir.begin(), stepsPir.end());
        unionSet.insert(stepsPr.begin(), stepsPr.end());
        unionSet.insert(1); unionSet.insert(16);
        galois_step_set_.assign(unionSet.begin(), unionSet.end());

        cout << " [P1] Galois key step set size = " << galois_step_set_.size()
             << " (was " << nGlobal << " in pre-P1 default)" << endl;

        auto start_time = chrono::high_resolution_clock::now();
        InitializeFHE();
        auto end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Initialize FHE : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;

        int targetGlobalIdx = -1;
        // [Q5] M_pub 을 sparse 로 할당. nGlobal=4096 시 dense 128MB → sparse ~150KB.
        SparseMatrix M_pub(nGlobal);

        // Phase 1 (B: sparse + Q7 padding, β·thr injected)
        start_time = chrono::high_resolution_clock::now();
        int D_sparse = 0;
        vector<BsgsDiag> pirDiagonals = PreparePublicData(M_pub, pirParams.m1, pirParams.m2,
                                                         beta1_, beta2_, prune_threshold_,
                                                         D_sparse);
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 1 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;

        // B8 (spec sec 5.10): D_sparse < 2*sqrt(N) 시 BSGS 비용 (m1+m2-2) 가 직접 rotation 비용 D 보다 큼.
        // 현 구현은 detection + 로그만; main-style 분기는 별도 작업.
        int D_threshold = static_cast<int>(2 * sqrt(static_cast<double>(nGlobal)));
        if (D_sparse > 0 && D_sparse < D_threshold) {
            cout << "   [B8] D_sparse=" << D_sparse << " < " << D_threshold
                 << " — BSGS rotation count exceeds direct rotation count (informational)." << endl;
        }

        if (num_targets == 0) {
            cout << "[INFO] No valid target wallets found. Terminating pipeline." << endl;
            return;
        }
        
        // Phase 2
        start_time = chrono::high_resolution_clock::now();
        vector<Ciphertext> cipherTarget = EncryptTargets();
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 2 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;
        
        // Phase 3
        start_time = chrono::high_resolution_clock::now();
        vector<Ciphertext> cipherNeighbors = ExtractBlindSubgraph(cipherTarget, pirDiagonals, pirParams.m1, pirParams.m2);
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 3 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;
        
        // Phase 4
        start_time = chrono::high_resolution_clock::now();
        vector<vector<int>> allTopNodesIndices;
        vector<int> allTargetSubIdx;
        ResolveSubgraphIndices(cipherNeighbors, allTopNodesIndices, allTargetSubIdx);
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 4 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;
        
        // Phase 5 & 6
        start_time = chrono::high_resolution_clock::now();
        EvaluatePageRank(allTopNodesIndices, M_pub, allTargetSubIdx);
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 5 & 6 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;

        auto total_end = chrono::high_resolution_clock::now();
        cout << "\n========================================================" << endl;
        cout << "[Total Timer] Total Pipeline Completed : " << chrono::duration<double>(total_end - total_start).count() << " sec" << endl;
        cout << "========================================================" << endl;
    }

private:
    /// <summary>
    /// CKKS 암호화 스키마를 사용하여 Microsoft SEAL 컨텍스트 및 키, 인코더, 평가기 등을 초기화합니다.
    /// </summary>
    void InitializeFHE() {
        EncryptionParameters parms(scheme_type::ckks);
        
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 45, 45, 60 }));

        context = make_shared<SEALContext>(parms);
        KeyGenerator keygen(*context);

        keygen.create_public_key(public_key);
        secret_key = keygen.secret_key();

        // P1: 미리 계산된 step set (Phase 3 + Phase 5 의 BSGS step 합집합) 만 생성.
        // 이전: {1..nGlobal} 모든 step → O(N) keys. 현재: O(m1_pir + m2_pir + m1_pr + m2_pr).
        if (galois_step_set_.empty()) {
            // 안전망: SetGaloisStepSet 호출 안 됐을 때 기존 동작 유지.
            for (int i = 1; i <= nGlobal; i++) galois_step_set_.push_back(i);
        }
        keygen.create_galois_keys(galois_step_set_, galois_keys);

        encoder = make_unique<CKKSEncoder>(*context);
        encryptor = make_unique<Encryptor>(*context, public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, secret_key);

        slot_count = encoder->slot_count();
        scale = pow(2.0, 45);

        if (pirInnerDim > pirBlockSize / 2) throw runtime_error("PIR block design invalid: potential cross-contamination");
        if (prInnerDim > prBlockSize / 2) throw runtime_error("PageRank block design invalid: potential cross-contamination");
    }

    /// <summary>
    /// 로컬 트랜잭션 데이터를 로드하여 글로벌 퍼블릭 매트릭스를 구성하고,
    /// sparse 인접 리스트 기반 β-weighted 2-hop 누적 + Q7 padding 으로 BsgsDiag 를 생성합니다.
    /// (Stage B: A1 BSGS 인코딩 + A2 sparse 알고리즘 + Q7 padding bridge 통합)
    /// </summary>
    /// <param name="outM_pub">Time-decay 가 적용된 1-Hop 매트릭스 (Phase 5 에서 사용).</param>
    /// <param name="m1">BSGS baby step 크기.</param>
    /// <param name="m2">BSGS giant step 크기.</param>
    /// <param name="beta1">1-hop 가중치 (default 1.0).</param>
    /// <param name="beta2">2-hop 가중치 (default 0.30, A2 semantic).</param>
    /// <param name="prune_threshold">2-hop 전파 차단 임계값 (default 0.05).</param>
    /// <param name="D_sparse_out">비영 BsgsDiag 갯수 (B2 cost function 입력).</param>
    /// <returns>BsgsDiag (i, j, plain) 리스트. Q7 padding 으로 row ∈ [0, 2N) 채움.</returns>
    vector<BsgsDiag> PreparePublicData(SparseMatrix& outM_pub, int m1, int m2,
                                       double beta1, double beta2, double prune_threshold,
                                       int& D_sparse_out) {
        cout << "\n[Phase 1] Server: Public Transaction Matrix Preparation (sparse + Q7 padding)" << endl;
        cout << "   [B-config] beta1=" << beta1 << ", beta2=" << beta2
             << ", prune_threshold=" << prune_threshold << endl;

        string snapFilePath = "../soc-sign-bitcoinotc.csv";
        ifstream file(snapFilePath);
        vector<Edge> rawEdges;
        unordered_map<int, int> frequency;
        int maxTime = 0;

        if (file.is_open()) {
            string line;
            while (getline(file, line)) {
                if (line.empty() || line[0] == '#') continue;
                stringstream ss(line);
                string token;
                vector<int> parts;
                while (getline(ss, token, ',')) {
                    try { parts.push_back(stoi(token)); } catch (...) {}
                }
                if (parts.size() < 4) continue;

                if (parts[2] >= 2) {
                    rawEdges.push_back({parts[0], parts[1], parts[2], parts[3]});
                    frequency[parts[0]]++;
                    frequency[parts[1]]++;
                    if (parts[3] > maxTime) maxTime = parts[3];
                }
            }
        }

        vector<pair<int, int>> freqVec(frequency.begin(), frequency.end());
        sort(freqVec.begin(), freqVec.end(), [](const pair<int, int>& a, const pair<int, int>& b) { return a.second > b.second; });

        unordered_map<int, int> globalNodeToIndex;
        for (size_t i = 0; i < min((size_t)freqVec.size(), (size_t)nGlobal); i++) {
            globalNodeToIndex[freqVec[i].first] = i;
        }


        for (int tid : requestedWalletIds) {
            if (globalNodeToIndex.count(tid)) {
                validWalletIds.push_back(tid);
                targetGlobalIndices.push_back(globalNodeToIndex[tid]);
            } else {
                cout << " [WARNING] Wallet ID " << tid << " is out of range." << endl;
            }
        }

        num_targets = validWalletIds.size();
        
        int pirCapacity = static_cast<int>(slot_count / pirBlockSize);
        int prCapacity  = static_cast<int>(slot_count / prBlockSize);
        batch_size = min(pirCapacity, prCapacity);
        num_chunks = ceil(static_cast<double>(num_targets) / batch_size);

        // 1-hop: outM_pub (Phase 5 용 dense) + outAdj (sparse 알고리즘 용 인접 리스트)
        vector<vector<pair<int, double>>> outAdj(nGlobal);
        double HALF_LIFE = 365.0 * 24.0 * 60.0 * 60.0;
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

        // [B3] Phase 1 OMP — per-thread sparseDiag_local + 결정론적 sequential reduce.
        // [Q4] reduce 후 per-diag entry 를 row 오름차순으로 정렬 → cross-run FP 누적 순서 결정성.
        int num_threads = omp_get_max_threads();
        vector<vector<unordered_map<int, double>>> tlSparseDiag(num_threads,
            vector<unordered_map<int, double>>(nGlobal));

        #pragma omp parallel
        {
            int tid = omp_get_thread_num();
            auto& localDiag = tlSparseDiag[tid];
            #pragma omp for schedule(static)
            for (int src = 0; src < nGlobal; src++) {
                for (const auto& [mid, w1] : outAdj[src]) {
                    int d1 = (src - mid + nGlobal) % nGlobal;
                    localDiag[d1][mid] += beta1 * w1;

                    if (w1 < prune_threshold) continue;

                    for (const auto& [dst, w2] : outAdj[mid]) {
                        int d2 = (src - dst + nGlobal) % nGlobal;
                        localDiag[d2][dst] += beta2 * w1 * w2;
                    }
                }
            }
        }

        // Reduce: thread_id 0..P-1 순서로 sequential 합산 → FP 결합 결정론.
        // 그 후 Q4: 각 d 의 entry 를 row 오름차순 sorted vector 로 변환.
        vector<vector<pair<int, double>>> sparseDiag(nGlobal);
        {
            vector<map<int, double>> merged(nGlobal);  // std::map = sorted by row
            for (int t = 0; t < num_threads; t++) {
                for (int d = 0; d < nGlobal; d++) {
                    for (const auto& [row, val] : tlSparseDiag[t][d]) {
                        merged[d][row] += val;
                    }
                }
            }
            for (int d = 0; d < nGlobal; d++) {
                sparseDiag[d].assign(merged[d].begin(), merged[d].end());
            }
        }

        // BsgsDiag 인코딩 with Q7 padding (row ∈ [0, 2N)). thread-local CKKSEncoder (P5a 패턴).
        vector<BsgsDiag> pirDiagonals;
        {
            // (j, i) → 비영 (d) 만 모아 OMP 분배.
            vector<pair<int,int>> work;  // (j, i) 쌍 nonzero 만
            for (int j = 0; j < m2; j++) {
                for (int i = 0; i < m1; i++) {
                    int d = j * m1 + i;
                    if (d >= nGlobal) continue;
                    if (sparseDiag[d].empty()) continue;
                    work.push_back({j, i});
                }
            }
            vector<BsgsDiag> results(work.size());
            #pragma omp parallel for schedule(dynamic)
            for (size_t k = 0; k < work.size(); k++) {
                int j = work[k].first, i = work[k].second;
                int d = j * m1 + i;
                CKKSEncoder thr_encoder(*context);

                vector<double> diag(slot_count, 0.0);
                // Q7 padding: row ∈ [0, 2N) 채움. inverse map orig_row 가 chunk-translation invariance 보존.
                for (size_t c = 0; c < batch_size; c++) {
                    for (const auto& [row, val] : sparseDiag[d]) {
                        // row 위치 1: orig_row == row 일 때 → row index = (row + j*m1) mod N (within chunk)
                        // padding 둘 다 채우려면 row index ∈ {a, a + N} 위치 모두에 동일 값.
                        int slot_idx = (row + j * m1) % nGlobal;
                        diag[c * pirBlockSize + slot_idx] = val;
                        diag[c * pirBlockSize + slot_idx + nGlobal] = val;  // Q7
                    }
                }
                Plaintext plainDiag;
                thr_encoder.encode(diag, scale, plainDiag);
                results[k] = {i, j, plainDiag};
            }
            pirDiagonals = std::move(results);
        }
        D_sparse_out = static_cast<int>(pirDiagonals.size());
        cout << "   [B-stat] D_sparse = " << D_sparse_out << " / " << nGlobal
             << " (sparsity = " << (1.0 - static_cast<double>(D_sparse_out) / nGlobal) << ")"
             << ", OMP_threads = " << num_threads << endl;
        return pirDiagonals;
    }

    /// <summary>
    /// 클라이언트에서 타겟 지갑들의 인덱스를 기반으로 One-Hot Vector를 생성하고 이를 SIMD 방식으로 암호화합니다.
    /// </summary>
    /// <returns>서버에 전송하기 위해 다수의 타겟이 하나의 배열에 병렬로 암호화된 암호문입니다.</returns>
    vector<Ciphertext> EncryptTargets() {
        cout << "\n[Phase 2] Client: " << num_chunks << "Multi-Target SIMD FHE-PIR Encryption" << endl;
        vector<Ciphertext> cipherChunks;

        for (int k = 0; k < num_chunks; k++) {
            vector<double> v_target(slot_count, 0.0);
            int start_idx = k * batch_size;
            int end_idx = min(static_cast<int>(num_targets), start_idx + batch_size);
            
            for (int c = 0; c < (end_idx - start_idx); c++) {
                int idx = targetGlobalIndices[start_idx + c];
                v_target[c * pirBlockSize + idx] = 1.0;
                v_target[c * pirBlockSize + pirInnerDim + idx] = 1.0;
            }
            Plaintext plainTarget; encoder->encode(v_target, scale, plainTarget);
            Ciphertext cipherTarget; encryptor->encrypt(plainTarget, cipherTarget);
            cipherChunks.push_back(cipherTarget);
        }
        return cipherChunks;
    }

    // <summary>
    /// 서버가 타겟의 위치를 모르는 상태에서 캐싱된 대각선 평문과 타겟 암호문 배열(Chunks)을 동형 곱셈하여,
    /// 여러 청크에 분산된 타겟들의 이웃 서브그래프를 병렬로 추출합니다.
    /// </summary>
    /// <param name="cipherChunks">클라이언트로부터 수신한 병렬 타겟 지갑들의 암호문 배열(Chunking 적용)입니다.</param>
    /// <param name="pirDiagonals">사전 연산되어 캐싱된 퍼블릭 매트릭스의 대각선 평문 리스트입니다.</param>
    /// <returns>각 청크별로 동형 추출된 이웃 가중치가 담긴 암호문 배열입니다.</returns>
    vector<Ciphertext> ExtractBlindSubgraph(const vector<Ciphertext>& cipherChunks, const vector<BsgsDiag>& pirDiagonals, int m1, int m2) {
        cout << "\n[Phase 3] Server: Parallel Blind Subgraph Extraction" << endl;
        vector<Ciphertext> neighborsChunks(num_chunks);

        #pragma omp parallel for
        for (int k = 0; k < num_chunks; k++) {
            Evaluator thread_evaluator(*context);

            vector<Ciphertext> baby_steps(m1);
            baby_steps[0] = cipherChunks[k];
            for (int i = 1; i < m1; i++) {
                thread_evaluator.rotate_vector(cipherChunks[k], i, galois_keys, baby_steps[i]);
            }

            Ciphertext cipherNeighbors; 
            bool isInit = false;

            for (int j = 0; j < m2; j++) {
                Ciphertext giant_acc; 
                bool isGiantInit = false;

                for (const auto& item : pirDiagonals) {
                    if (item.j != j) continue;
                    
                    Ciphertext multiplied = baby_steps[item.i]; 
                    thread_evaluator.multiply_plain_inplace(multiplied, item.plain);
                    thread_evaluator.rescale_to_next_inplace(multiplied);
                    multiplied.scale() = scale;

                    if (!isGiantInit) { 
                        giant_acc = multiplied; 
                        isGiantInit = true; 
                    } else {
                        thread_evaluator.mod_switch_to_inplace(giant_acc, multiplied.parms_id());
                        giant_acc.scale() = multiplied.scale();
                        thread_evaluator.add_inplace(giant_acc, multiplied);
                    }
                }

                if (isGiantInit) {
                    if (j > 0) {
                        thread_evaluator.rotate_vector_inplace(giant_acc, j * m1, galois_keys);
                    }

                    if (!isInit) { 
                        cipherNeighbors = giant_acc; 
                        isInit = true; 
                    } else {
                        thread_evaluator.mod_switch_to_inplace(cipherNeighbors, giant_acc.parms_id());
                        cipherNeighbors.scale() = giant_acc.scale();
                        thread_evaluator.add_inplace(cipherNeighbors, giant_acc);
                    }
                }
            }
            neighborsChunks[k] = cipherNeighbors;
        }
        return neighborsChunks;
    }

    /// <summary>
    /// 여러 개의 청크로 나뉜 이웃 가중치 암호문 배열을 복호화하여, 
    /// 각 타겟별로 서브그래프를 구성할 상위 핵심 노드들의 인덱스를 매핑합니다.
    /// </summary>
    /// <param name="neighborsChunks">Phase 3에서 병렬 추출된 암호문 배열(Chunks)입니다.</param>
    /// <param name="outTopNodes">각 타겟별로 nSub차원 서브그래프를 구성할 최상위 노드들의 인덱스 목록이 반환됩니다.</param>
    /// <param name="outTargetSubIdx">각 타겟이 nSub차원 서브그래프 내에서 몇 번째 인덱스에 위치하는지 반환됩니다.</param>
    void ResolveSubgraphIndices(const vector<Ciphertext>& neighborsChunks, vector<vector<int>>& outTopNodes, vector<int>& outTargetSubIdx) {
        cout << "\n[Phase 4] Client: SIMD Subgraph Resolution & Mapping" << endl;
        
        for (int k = 0; k < num_chunks; k++) {
            Plaintext decryptedNeighbors;
            decryptor->decrypt(neighborsChunks[k], decryptedNeighbors);
            vector<double> decodedNeighbors;
            encoder->decode(decryptedNeighbors, decodedNeighbors);
            int start_idx = k * batch_size;
            int end_idx = min(static_cast<int>(num_targets), start_idx + batch_size);

            struct Score { int index; double score; };

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
                if (find(topNodes.begin(), topNodes.end(), targetGIdx) == topNodes.end()) topNodes[nSub - 1] = targetGIdx;

                int subIdx = -1;
                for (int i = 0; i < nSub; i++) { if (topNodes[i] == targetGIdx) { subIdx = i; break; } }
                
                outTopNodes.push_back(topNodes);
                outTargetSubIdx.push_back(subIdx);
            }
        }
    }

    /// <summary>
    /// 청크(Chunk) 단위로 쪼개진 서브그래프 위에서 동형암호 기반의 병렬 PageRank 거듭제곱 루프를 실행하고, 
    /// 평문 연산 결과와 비교하여 오차율을 검증합니다.
    /// </summary>
    /// <param name="allTop">각 타겟별 서브그래프를 구성하는 핵심 노드들의 인덱스 목록입니다.</param>
    /// <param name="M_pub">전역 퍼블릭 매트릭스 원본입니다.</param>
    /// <param name="allTargetSubIdx">각 서브그래프 내 타겟 지갑들의 인덱스 배열입니다.</param>
    void EvaluatePageRank(const vector<vector<int>>& allTopNodes, const SparseMatrix& M_pub, const vector<int>& allTargetSubIdx) {
        cout << "\n[Phase 5] FHE & Plaintext PageRank Iteration (Executing " << num_chunks << " Chunks)" << endl;

        vector<vector<vector<double>>> all_M_sub(num_targets, vector<vector<double>>(nSub, vector<double>(nSub, 0.0)));
        vector<vector<double>> all_plainV(num_targets, vector<double>(nSub, 1.0 / nSub));
        vector<vector<double>> logicalV(num_targets, vector<double>(nSub, 1.0 / nSub));

        for (size_t c = 0; c < num_targets; c++) {
            for (int i = 0; i < nSub; i++) {
                // [Q5] sparse M_pub read via SparseGet (const-safe; operator[] 회피).
                for (int j = 0; j < nSub; j++)
                    all_M_sub[c][i][j] = SparseGet(M_pub, allTopNodes[c][i], allTopNodes[c][j]);
            }
            double alpha = 0.85, tele = (1.0 - alpha) / nSub;
            for (int j = 0; j < nSub; j++) {
                double colSum = 0.0;
                for (int i = 0; i < nSub; i++) colSum += all_M_sub[c][i][j];
                if (colSum == 0.0) all_M_sub[c][j][j] = 1.0;
                else for (int i = 0; i < nSub; i++) all_M_sub[c][i][j] /= colSum;
                for (int i = 0; i < nSub; i++) all_M_sub[c][i][j] = (alpha * all_M_sub[c][i][j]) + tele;
            }
        }

        int ITERATIONS = 10;
        for (int iter = 1; iter <= ITERATIONS; iter++) {
            for (size_t c = 0; c < num_targets; c++) {
                vector<double> nextV(nSub, 0.0);
                for (int j = 0; j < nSub; j++) {
                    for (int i = 0; i < nSub; i++) nextV[i] += all_M_sub[c][i][j] * all_plainV[c][j];
                }
                all_plainV[c] = nextV;
            }
        }

        cout << " [Auto-Tune] Measuring the rotation cost of the current system..." << endl;
        
        Plaintext dummy_plain;
        encoder->encode(vector<double>(pirBlockSize, 1.0), scale, dummy_plain);
        Ciphertext dummy_cipher;
        encryptor->encrypt(dummy_plain, dummy_cipher); 

        auto start_baby = chrono::high_resolution_clock::now();
        Ciphertext rotated_baby;
        evaluator->rotate_vector(dummy_cipher, 1, galois_keys, rotated_baby);
        auto end_baby = chrono::high_resolution_clock::now();
        double baby_time = chrono::duration<double>(end_baby - start_baby).count();

        auto start_giant = chrono::high_resolution_clock::now();
        Ciphertext rotated_giant;
        evaluator->rotate_vector(dummy_cipher, 16, galois_keys, rotated_giant);
        auto end_giant = chrono::high_resolution_clock::now();
        double giant_time = chrono::duration<double>(end_giant - start_giant).count();

        double real_weight = (baby_time > 0) ? (giant_time / baby_time) : 1.0;
        
        if (real_weight < 1.0) real_weight = 1.0; 
        if (real_weight > 5.0) real_weight = 5.0;

        cout << "   -> Baby Step:  " << baby_time << " sec" << endl;
        cout << "   -> Giant Step: " << giant_time << " sec" << endl;
        cout << "   -> [Result] Giant/Baby weight: " << real_weight << "times" << endl;

        BSGSParams params = FindOptimalAsymmetricBSGS(nSub, real_weight);
        int m1 = params.m1; // Baby-Step 크기
        int m2 = params.m2;  // Giant-Step 크기

        // FHE 병렬 PageRank 계산 (Chunk 단위 처리)
        #pragma omp parallel for
        for (int k = 0; k < num_chunks; k++) {
            // P5a: thread-local SEAL 객체. Phase 3와 일관된 격리 패턴.
            // galois_keys/public_key/secret_key 는 const read이므로 공유 안전.
            Evaluator   thr_eval(*context);
            Encryptor   thr_enc(*context, public_key);
            Decryptor   thr_dec(*context, secret_key);
            CKKSEncoder thr_encoder(*context);

            int start_idx = k * batch_size;
            int end_idx = min(static_cast<int>(num_targets), start_idx + batch_size);
            int current_batch = end_idx - start_idx;

            vector<BsgsDiag> bsgs_diagonals;
            for (int j = 0; j < m2; j++) {
                for (int i = 0; i < m1; i++) {
                    int d = j * m1 + i;
                    if (d >= nSub) continue;

                    vector<double> diag(slot_count, 0.0);
                    bool isZero = true;
                    for (int c = 0; c < current_batch; c++) {
                        // Duplicate Padding 영역까지 덮도록 nSub * 2 (128) 반복
                        for (int row = 0; row < nSub * 2; row++) {
                            // 수학적 역방향 시프트 (음수 모듈러 연산 방지)
                            int orig_row = ((row - j * m1) % nSub + nSub) % nSub;
                            double val = all_M_sub[start_idx + c][orig_row][(orig_row + d) % nSub];
                            diag[c * prBlockSize + row] = val;
                            if (val > 0.0) isZero = false;
                        }
                    }
                    if (!isZero) {
                        Plaintext plainDiag; thr_encoder.encode(diag, scale, plainDiag);
                        bsgs_diagonals.push_back({i, j, plainDiag});
                    }
                }
            }

            for (int iter = 1; iter <= ITERATIONS; iter++) {
                vector<double> vRepeated(slot_count, 0.0);
                for (size_t c = 0; c < current_batch; c++) {
                    for (int i = 0; i < nSub; i++) {
                        vRepeated[c * prBlockSize + i] = logicalV[start_idx + c][i];
                        vRepeated[c * prBlockSize + prInnerDim + i] = logicalV[start_idx + c][i];
                    }
                }

                Plaintext plainVEnc;
                thr_encoder.encode(vRepeated, scale, plainVEnc);
                Ciphertext cipherV;
                thr_enc.encrypt(plainVEnc, cipherV);

                vector<Ciphertext> baby_steps(m1);
                baby_steps[0] = cipherV;
                for (int i = 1; i < m1; i++) {
                    thr_eval.rotate_vector(cipherV, i, galois_keys, baby_steps[i]);
                }

                Ciphertext cipherResult;
                bool isResultInitialized = false;

                for (int j = 0; j < m2; j++) {
                    Ciphertext giant_acc; bool isGiantInit = false;

                    for (const auto& item : bsgs_diagonals) {
                        if (item.j != j) continue;
                        Ciphertext multiplied;
                        thr_eval.multiply_plain(baby_steps[item.i], item.plain, multiplied);
                        thr_eval.rescale_to_next_inplace(multiplied); multiplied.scale() = scale;

                        if (!isGiantInit) { giant_acc = multiplied; isGiantInit = true; }
                        else {
                            thr_eval.mod_switch_to_inplace(giant_acc, multiplied.parms_id());
                            giant_acc.scale() = multiplied.scale();
                            thr_eval.add_inplace(giant_acc, multiplied);
                        }
                    }

                    if (isGiantInit) {
                        if (j > 0) thr_eval.rotate_vector(giant_acc, j * m1, galois_keys, giant_acc);

                        if (!isResultInitialized) { cipherResult = giant_acc; isResultInitialized = true; }
                        else {
                            thr_eval.mod_switch_to_inplace(cipherResult, giant_acc.parms_id());
                            cipherResult.scale() = giant_acc.scale();
                            thr_eval.add_inplace(cipherResult, giant_acc);
                        }
                    }
                }

                Plaintext decrypted;
                thr_dec.decrypt(cipherResult, decrypted);
                vector<double> decoded;
                thr_encoder.decode(decrypted, decoded);

                for(size_t c = 0; c < current_batch; c++) {
                    double sum = 0.0;
                    for(int i = 0; i < nSub; i++) {
                        double val = max(0.0, decoded[c * prBlockSize + i]); 
                        logicalV[start_idx + c][i] = val; 
                        sum += val;
                    }
                    if (sum == 0.0) {
                       for(int i = 0; i < nSub; i++) logicalV[start_idx + c][i] = 1.0 / nSub;
                    } else {
                       for(int i = 0; i < nSub; i++) logicalV[start_idx + c][i] /= sum;
                    }
                }
            }
        } 

        cout << "\n[Phase 6] Precision Validation & Smart Contract Logic" << endl;
        cout << fixed << setprecision(6);
        
        for (size_t c = 0; c < num_targets; c++) {
            double fheScore = logicalV[c][allTargetSubIdx[c]];
            double groundTruthScore = all_plainV[c][allTargetSubIdx[c]];
            double errorRate = abs(fheScore - groundTruthScore);

            cout << "--------------------------------------------------------" << endl;
            cout << " Target Wallet ID : " << validWalletIds[c] << endl;
            cout << " Plaintext Score  : " << groundTruthScore << endl;
            cout << " FHE Engine Score : " << fheScore << endl;
            cout << " Precision Error  : " << errorRate << endl;
            if (fheScore >= 0.0150) cout << "[APPROVED] Minimum threshold met." << endl;
            else cout << "[REJECTED] Insufficient trust score." << endl;
        }
        cout << "--------------------------------------------------------" << endl;
    }
};

/// <summary>
/// 프로그램의 엔트리포인트입니다.
/// 명령줄 인자(Command-line arguments)를 통해 무제한으로 검증할 모든 타겟 지갑 ID를 동적으로 받습니다.
/// </summary>
/// <param name="argc">전달된 인자의 개수입니다.</param>
/// <param name="argv">실행 명령어와 인자들을 담고 있는 문자열 배열입니다.</param>
/// <returns>정상 종료 시 0을 반환합니다.</returns>
int main(int argc, char* argv[]) {
    omp_set_num_threads(4);
    
    try {
        vector<int> targetIds;

        int req_nGlobal = 256;
        int req_nSub = 64;

        // B1 minimal: β·thr CLI flags
        double req_beta1 = 1.0;
        double req_beta2 = 0.30;
        double req_thr = 0.05;

        for (int i = 1; i < argc; i++) {
            string arg = argv[i];
            if (arg == "-g" && i + 1 < argc) {
                req_nGlobal = stoi(argv[++i]);
            } else if (arg == "-s" && i + 1 < argc) {
                req_nSub = stoi(argv[++i]);
            } else if (arg == "-b1" && i + 1 < argc) {
                req_beta1 = stod(argv[++i]);
            } else if (arg == "-b2" && i + 1 < argc) {
                req_beta2 = stod(argv[++i]);
            } else if (arg == "-thr" && i + 1 < argc) {
                req_thr = stod(argv[++i]);
            } else {
                targetIds.push_back(stoi(arg));
            }
        }

        if (targetIds.empty()) {
            targetIds = {1, 2, 4, 35};
        }

        // 타겟 1개를 안전하게 담고 회전시키기 위한 최소 칸 수는 nGlobal * 2
        int min_required_slots = req_nGlobal * 2;
        
        // CKKS 보안 강도를 유지하기 위한 최소 시작 사이즈 (슬롯 4096개)
        size_t poly_degree = 8192; 
        
        // 입력된 nGlobal이 너무 크다면, poly_degree를 2배씩 늘려서 자동으로 맞춤
        while ((poly_degree / 2) < min_required_slots) {
            poly_degree *= 2;
        }

        cout << "========================================================" << endl;
        cout << " [Init] Multi-Target SIMD Pipeline Auto-Configuration " << endl;
        cout << "  -> Requested nGlobal : " << req_nGlobal << endl;
        cout << "  -> Requested nSub    : " << req_nSub << endl;
        cout << "  -> Auto-tuned Poly   : " << poly_degree << " (Slots: " << (poly_degree/2) << ")" << endl;
        cout << "  -> [B-config] beta1=" << req_beta1 << ", beta2=" << req_beta2
             << ", thr=" << req_thr << endl;
        cout << "========================================================" << endl;

        UltimatePrivacyPipeline pipeline(targetIds, req_nGlobal, req_nSub, poly_degree);
        pipeline.SetConfig(req_beta1, req_beta2, req_thr);
        pipeline.RunPipeline();
        
    } catch (const exception& e) {
        cerr << "Error occurred: " << e.what() << endl;
        return 1;
    }
    return 0;
}
