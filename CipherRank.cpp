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
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <iomanip>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;

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
/// 동형암호 PIR 연산을 위해 캐싱된 대각선 평문 데이터를 표현하는 구조체입니다.
/// </summary>
struct PirDiag {
    /// <summary>대각선 시프트 인덱스입니다.</summary>
    int d;
    
    /// <summary>인코딩된 대각선 평문 데이터입니다.</summary>
    Plaintext plain;
};

/// <summary>
/// 데이터 조작을 차단하기 위한 서버 측 전처리와, 
/// 타겟 익명성을 보장하는 클라이언트 측 블라인드 추출(PIR), 그리고 오차 검증을 총괄하는 코어 클래스입니다.
/// </summary>
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

    shared_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    GaloisKeys galois_keys;
    
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
    /// 전체 시빌 방어 파이프라인을 순차적으로 실행하며 각 Phase별 소요 시간을 측정하는 메인 엔트리 API입니다.
    /// </summary>
    void RunPipeline() {
        auto total_start = chrono::high_resolution_clock::now();

        auto start_time = chrono::high_resolution_clock::now();
        InitializeFHE();
        auto end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Initialize FHE : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;

        int targetGlobalIdx = -1;
        vector<vector<double>> M_pub(nGlobal, vector<double>(nGlobal, 0.0));
        
        // Phase 1
        start_time = chrono::high_resolution_clock::now();
        vector<PirDiag> pirDiagonals = PreparePublicData(M_pub);
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 1 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;

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
        vector<Ciphertext> cipherNeighbors = ExtractBlindSubgraph(cipherTarget, pirDiagonals);
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 3 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;
        
        // Phase 4
        start_time = chrono::high_resolution_clock::now();
        vector<vector<int>> allTop64Indices;
        vector<int> allTargetSubIdx;
        ResolveSubgraphIndices(cipherNeighbors, allTop64Indices, allTargetSubIdx);
        end_time = chrono::high_resolution_clock::now();
        cout << "[Timer] Phase 4 Completed : " << chrono::duration<double>(end_time - start_time).count() << " sec" << endl;
        
        // Phase 5 & 6
        start_time = chrono::high_resolution_clock::now();
        EvaluatePageRank(allTop64Indices, M_pub, allTargetSubIdx);
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
        
        PublicKey public_key;
        keygen.create_public_key(public_key);
        SecretKey secret_key = keygen.secret_key();
        keygen.create_galois_keys(galois_keys);

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
    /// 로컬 트랜잭션 데이터를 로드하고, 먼지 트랜잭션을 가지치기하여
    /// 글로벌 퍼블릭 매트릭스(<paramref name="outM_pub"/>)와 블라인드 탐색용 대각선 캐싱 데이터를 생성합니다.
    /// </summary>
    /// <param name="outM_pub">Time-decay가 적용된 글로벌 퍼블릭 매트릭스가 반환됩니다.</param>
    /// <returns>PIR 연산을 위해 1-Hop, 2-Hop이 모두 포함되어 대각선 패킹된 평문 리스트입니다.</returns>
    vector<PirDiag> PreparePublicData(vector<vector<double>>& outM_pub) {
        cout << "\n[Phase 1] Server: Public Transaction Matrix Preparation" << endl;

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

        double HALF_LIFE = 365.0 * 24.0 * 60.0 * 60.0;
        for (const auto& edge : rawEdges) {
            if (globalNodeToIndex.count(edge.src) && globalNodeToIndex.count(edge.tgt)) {
                double decay = pow(0.5, (maxTime - edge.time) / HALF_LIFE);
                outM_pub[globalNodeToIndex[edge.tgt]][globalNodeToIndex[edge.src]] += (edge.weight * decay);
            }
        }

        vector<vector<double>> M_total(nGlobal, vector<double>(nGlobal, 0.0));
        for (int i = 0; i < nGlobal; i++) {
            for (int j = 0; j < nGlobal; j++) {
                M_total[i][j] = outM_pub[i][j];
                for (int k = 0; k < nGlobal; k++) M_total[i][j] += outM_pub[i][k] * outM_pub[k][j];
            }
        }

        vector<PirDiag> pirDiagonals;
        for (int d = 0; d < nGlobal; d++) {
            vector<double> diag(slot_count, 0.0);
            bool isZero = true;
            for (size_t c = 0; c < batch_size; c++) {
                for (int row = 0; row < nGlobal; row++) {
                    double val = M_total[row][(row + d) % nGlobal];
                    diag[c * pirBlockSize + row] = val;
                    if (val > 0) isZero = false;
                }
            }
            if (!isZero) {
                Plaintext plainDiag;
                encoder->encode(diag, scale, plainDiag);
                pirDiagonals.push_back({d, plainDiag});
            }
        }
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
    vector<Ciphertext> ExtractBlindSubgraph(const vector<Ciphertext>& cipherChunks, const vector<PirDiag>& pirDiagonals) {
        cout << "\n[Phase 3] Server: Parallel Blind Subgraph Extraction" << endl;
        vector<Ciphertext> neighborsChunks;

        for (int k = 0; k < num_chunks; k++) {
            Ciphertext cipherNeighbors; bool isInit = false;
            for (const auto& item : pirDiagonals) {
                Ciphertext rotated, multiplied;
                evaluator->rotate_vector(cipherChunks[k], item.d, galois_keys, rotated);
                evaluator->multiply_plain(rotated, item.plain, multiplied);
                evaluator->rescale_to_next_inplace(multiplied);
                multiplied.scale() = scale;

                if (!isInit) { cipherNeighbors = multiplied; isInit = true; } 
                else {
                    evaluator->mod_switch_to_inplace(cipherNeighbors, multiplied.parms_id());
                    cipherNeighbors.scale() = multiplied.scale();
                    Ciphertext tmp; evaluator->add(cipherNeighbors, multiplied, tmp);
                    cipherNeighbors = tmp;
                }
            }
            neighborsChunks.push_back(cipherNeighbors);
        }
        return neighborsChunks;
    }

    /// <summary>
    /// 여러 개의 청크로 나뉜 이웃 가중치 암호문 배열을 복호화하여, 
    /// 각 타겟별로 서브그래프를 구성할 상위 핵심 노드들의 인덱스를 매핑합니다.
    /// </summary>
    /// <param name="neighborsChunks">Phase 3에서 병렬 추출된 암호문 배열(Chunks)입니다.</param>
    /// <param name="outTop64">각 타겟별로 64차원 서브그래프를 구성할 최상위 노드들의 인덱스 목록이 반환됩니다.</param>
    /// <param name="outTargetSubIdx">각 타겟이 64차원 서브그래프 내에서 몇 번째 인덱스에 위치하는지 반환됩니다.</param>
    void ResolveSubgraphIndices(const vector<Ciphertext>& neighborsChunks, vector<vector<int>>& outTop64, vector<int>& outTargetSubIdx) {
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

                vector<int> top64;
                for (int i = 0; i < nSub; i++) top64.push_back(scores[i].index);

                int targetGIdx = targetGlobalIndices[start_idx + c];
                if (find(top64.begin(), top64.end(), targetGIdx) == top64.end()) top64[nSub - 1] = targetGIdx;

                int subIdx = -1;
                for (int i = 0; i < nSub; i++) { if (top64[i] == targetGIdx) { subIdx = i; break; } }
                
                outTop64.push_back(top64);
                outTargetSubIdx.push_back(subIdx);
            }
        }
    }

    /// <summary>
    /// 청크(Chunk) 단위로 쪼개진 서브그래프 위에서 동형암호 기반의 병렬 PageRank 거듭제곱 루프를 실행하고, 
    /// 평문 연산 결과와 비교하여 오차율을 검증합니다.
    /// </summary>
    /// <param name="allTop64">각 타겟별 서브그래프를 구성하는 핵심 노드들의 인덱스 목록입니다.</param>
    /// <param name="M_pub">전역 퍼블릭 매트릭스 원본입니다.</param>
    /// <param name="allTargetSubIdx">각 서브그래프 내 타겟 지갑들의 인덱스 배열입니다.</param>
    void EvaluatePageRank(const vector<vector<int>>& allTop64, const vector<vector<double>>& M_pub, const vector<int>& allTargetSubIdx) {
        cout << "\n[Phase 5] FHE & Plaintext PageRank Iteration (Executing " << num_chunks << " Chunks)" << endl;

        vector<vector<vector<double>>> all_M_sub(num_targets, vector<vector<double>>(nSub, vector<double>(nSub, 0.0)));
        vector<vector<double>> all_plainV(num_targets, vector<double>(nSub, 1.0 / nSub));
        vector<vector<double>> logicalV(num_targets, vector<double>(nSub, 1.0 / nSub));

        for (size_t c = 0; c < num_targets; c++) {
            for (int i = 0; i < nSub; i++) {
                for (int j = 0; j < nSub; j++) all_M_sub[c][i][j] = M_pub[allTop64[c][i]][allTop64[c][j]];
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

        // FHE 병렬 PageRank 계산 (Chunk 단위 처리)
        for (int k = 0; k < num_chunks; k++) {
            int start_idx = k * batch_size;
            int end_idx = min(static_cast<int>(num_targets), start_idx + batch_size);
            int current_batch = end_idx - start_idx;

            vector<PirDiag> prDiagonals;
            for (int d = 0; d < nSub; d++) {
                vector<double> diag(slot_count, 0.0);
                bool isZero = true;
                for (size_t c = 0; c < current_batch; c++) {
                    for (int row = 0; row < nSub; row++) {
                        double val = all_M_sub[start_idx + c][row][(row + d) % nSub];
                        diag[c * prBlockSize + row] = val;
                        if (val > 0.0) isZero = false;
                    }
                }
                if (!isZero) {
                    Plaintext plainDiag;
                    encoder->encode(diag, scale, plainDiag);
                    prDiagonals.push_back({d, plainDiag});
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
                encoder->encode(vRepeated, scale, plainVEnc);
                Ciphertext cipherV;
                encryptor->encrypt(plainVEnc, cipherV);

                Ciphertext cipherResult;
                bool isResultInitialized = false;

                for (const auto& item : prDiagonals) {
                    Ciphertext rotated, multiplied;
                    evaluator->rotate_vector(cipherV, item.d, galois_keys, rotated);
                    evaluator->multiply_plain(rotated, item.plain, multiplied);
                    evaluator->rescale_to_next_inplace(multiplied);
                    multiplied.scale() = scale;

                    if (!isResultInitialized) {
                        cipherResult = multiplied;
                        isResultInitialized = true;
                    } else {
                        evaluator->mod_switch_to_inplace(cipherResult, multiplied.parms_id());
                        cipherResult.scale() = multiplied.scale();
                        Ciphertext tmp;
                        evaluator->add(cipherResult, multiplied, tmp);
                        cipherResult = tmp;
                    }
                }

                Plaintext decrypted;
                decryptor->decrypt(cipherResult, decrypted);
                vector<double> decoded; 
                encoder->decode(decrypted, decoded);

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
    try {
        vector<int> targetIds;

        int req_nGlobal = 256; 
        int req_nSub = 64;

        for (int i = 1; i < argc; i++) {
            string arg = argv[i];
            if (arg == "-g" && i + 1 < argc) {
                req_nGlobal = stoi(argv[++i]);
            } else if (arg == "-s" && i + 1 < argc) {
                req_nSub = stoi(argv[++i]);
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
        cout << "========================================================" << endl;

        UltimatePrivacyPipeline pipeline(targetIds, req_nGlobal, req_nSub, poly_degree);
        pipeline.RunPipeline();
        
    } catch (const exception& e) {
        cerr << "Error occurred: " << e.what() << endl;
        return 1;
    }
    return 0;
}
