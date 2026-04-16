cmake_minimum_required(VERSION 3.10)
project(CipherRank)

# C++ 17 표준 사용 (SEAL 필수 규격)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 시스템에 설치된 Microsoft SEAL 라이브러리 찾기
find_package(SEAL 4.1.2 REQUIRED)

# 실행 파일 생성 (이름: CipherRank)
add_executable(CipherRank CipherRank.cpp)

# OpenMP 설정 (맥북 Homebrew 경로 강제 지정)
set(OPENMP_PATH "/opt/homebrew/opt/libomp")

# 모든 라이브러리 연결 (PRIVATE 키워드로 통일하여 에러 방지)
target_link_libraries(CipherRank PRIVATE SEAL::seal)

# OpenMP 컴파일/링크 옵션 추가
target_include_directories(CipherRank PRIVATE ${OPENMP_PATH}/include)
target_compile_options(CipherRank PRIVATE -Xpreprocessor -fopenmp)
target_link_libraries(CipherRank PRIVATE "-L${OPENMP_PATH}/lib" -lomp)
