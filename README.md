# 🛡️ 인터넷 사용자 보호를 위한 DDoS 공격에 대한 AI 탐지 및 대응 서비스, ADOSI 🖥️

**ADOSI**는 **인터넷 사용자 보호를 위해 DDoS AI 탐지 및 대응을 제공하는 지능형 IPS(침입 방지 시스템)** 입니다. <br><br>
목표는 악의적인 DDoS 공격을 신속히 탐지하고 대응하여, 서비스의 가용성과 안정성을 유지하는 데 중점을 둔 서비스입니다.

## 📌 프로젝트 개요
프로젝트 기간: 2024.03.04 ~ 2024.06.12 <br><br>
과목명: 캡스톤 디자인<br><br>
팀명: ADOSI<br><br>
목표: 네트워크 트래픽의 실시간 분석과 DDoS 탐지를 통해 인터넷 사용자 및 서비스 제공자의 안정적인 네트워크 환경을 보장하는 웹 서비스

## 팀 구성

- **팀장 : 정권희**  
  데이터 전처리, 랜덤 포레스트 모델 구축

- **팀원 : 조나경**  
  DB 구축, 데이터셋 수집, 웹 백엔드, 모델과 웹 연동

- **팀원 : 김세린**  
  공격 시뮬레이션, 데이터 셋 수집

- **팀원 : 조수아**  
  웹 프론트엔드, 백엔드

- **팀원 : 황윤하**  
  공격 시물레이션


## 🛠️ 주요 기능
1. 실시간 트래픽 분석
  - 네트워크 트래픽 패턴을 실시간으로 모니터링하여 이상 징후 탐지.
2. DDoS 공격 탐지 및 방어
  - 머신러닝 기반 탐지 알고리즘(랜덤 포레스트)을 활용하여 DDoS 공격을 식별하고 자동 대응.

## ⚙️ 시스템 흐름도     
<img width="532" alt="스크린샷 2024-11-28 오후 7 34 18" src="https://github.com/user-attachments/assets/cce51de7-e275-46cb-b196-e4892fbd1ce5">

## 기능 소개
### 사용자가 활동하는 웹 페이지 화면 (지도, 메인, 가위바위보 페이지) 
<img width="539" alt="스크린샷 2024-11-28 오후 7 45 06" src="https://github.com/user-attachments/assets/cff1545b-b44a-469c-8ea5-cfab605645ec">
<img width="511" alt="스크린샷 2024-11-28 오후 7 45 21" src="https://github.com/user-attachments/assets/b9d8bcd7-ecc8-4cff-a037-269e2d84489a">
<img width="493" alt="스크린샷 2024-11-28 오후 7 45 30" src="https://github.com/user-attachments/assets/39859fa3-8d5a-4dd1-962c-24dcbd889563">

### 실시간 트래픽을 분석후 랜덤 포레스트 모델을 적용하여 판단하여 로그에 표시
<img width="612" alt="스크린샷 2024-11-28 오후 7 47 21" src="https://github.com/user-attachments/assets/c894776e-9674-4cda-936c-481574625203">
<img width="671" alt="스크린샷 2024-11-28 오후 7 48 07" src="https://github.com/user-attachments/assets/bb18cc96-066d-495c-9a49-5b9c581b5590">

### 관리자 페이지에서 공격이 감지 되었을때, 경고문 확인
Validation IP 주소 목록을 관리하여 공격 탐지 시에도 허용된 IP만 접근할수 있도록 함. <br>
<img width="290" alt="스크린샷 2024-11-28 오후 7 48 28" src="https://github.com/user-attachments/assets/07d52e4a-c1dc-4034-b58f-19dfa670af17">
