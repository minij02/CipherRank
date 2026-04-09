cmake_minimum_required(VERSION 3.10)
project(CipherRank)

# C++ 17 표준 사용 (SEAL 필수 규격)
set(CMAKE_CXX_STANDARD 17)

# 시스템에 설치된 Microsoft SEAL 라이브러리 찾기
find_package(SEAL REQUIRED)

# 실행 파일 생성 (이름: CipherRank)
add_executable(CipherRank CipherRank.cpp)

# SEAL 라이브러리를 프로젝트에 링크
target_link_libraries(CipherRank SEAL::seal)
