# Kubernetes Installation Automation Tool — Software Requirements Specification (SRS) v1.0

- **작성 기준일:** 2026-10-10 (Asia/Seoul)
- **상태:** 요구사항 베이스라인 (설계 확정 전 검증 대상 포함), 구현/통합 테스트 이전
- **원본:** 사용자 확정 8차 요구사항 Q01~Q84, SRS v0.8
- **정규화:** 16개 상위 요구사항(12 FR, 4 NFR), 84개 하위 명세의 **단일 주 매핑**
- **문서 목적:** 오픈소스 GitHub 저장소에 구현·테스트·지원 정책을 연결할 수 있는 개발 기준

## 0. 문서 통제 및 용어

**MUST**는 준수해야 하는 요구, **SHOULD**는 강력 권장, **MAY**는 선택을 의미한다. 선택적 Add-on의 기능은 사용자가 활성화했을 때에만 MUST가 된다. Q번호는 원본 결정을 추적하는 영구 ID이며, FR/NFR 번호는 구현상 주 소유 모듈이다. 상위 범위 전체가 최초 릴리스에서 검증되었다는 뜻은 아니다.

**구현 정책:** 사전 구성 기반 무인 설치, Fail-Closed, Non-Destructive by Default, Idempotency, Reproducibility, 최소 권한, 로컬 우선 진단. 원본 사용자 결정을 임의 수정하지 않으며 기술적 불가능·미검증 조합은 명시적으로 BLOCKED 처리한다.

**지원 범위 구분:** (1) 프로젝트 최종 요구 범위, (2) 구현 완료, (3) 통합 테스트 통과, (4) 공식 지원을 구분한다. 이 문서 작성 시점의 설치 결과는 모두 미검증이다.

## 1. SRS v0.8 결과 및 정규화 설계

v0.8은 Q01~Q84의 확정 선택 집합이다. v1.0은 같은 선택을 기능별로 재분류한 구현·인수 명세이다. 모든 Q는 아래 **정확히 하나의 주 상위 요구사항**에 매핑하며, 상호 의존성은 별도 제약 조건으로 연결한다.

| 상위 ID | 명칭 | 원본 Q ID (주 매핑) | 개수 |
|---|---|---|---:|
| FR-01 | 지원 대상·토폴로지 | Q01, Q02, Q03, Q04, Q09, Q11 | 6 |
| FR-02 | 버전 선택·Container Runtime | Q06, Q07, Q08 | 3 |
| FR-03 | 호스트 사전 설정 | Q21, Q22, Q23, Q24 | 4 |
| FR-04 | Kubernetes 핵심 구성 | Q25, Q26, Q27, Q29, Q30, Q31, Q32, Q33 | 8 |
| FR-05 | Calico 및 네트워크 | Q13, Q14, Q15, Q16, Q17, Q18, Q19, Q20 | 8 |
| FR-06 | 안전한 원격·무인 오케스트레이션 | Q05, Q10, Q12, Q36, Q37, Q38, Q40, Q43, Q44, Q45, Q46 | 11 |
| FR-07 | CLI·설정 스키마 | Q39, Q41, Q42, Q76 | 4 |
| FR-08 | etcd 백업·관리자 접근·감사 | Q28, Q34, Q35 | 3 |
| FR-09 | 설치 후 기능 검증 | Q48, Q49, Q50, Q51 | 4 |
| FR-10 | 상태·Drift·복구 | Q47, Q52, Q53, Q54 | 4 |
| FR-11 | 안전한 노드·클러스터 제거 | Q55, Q56, Q57 | 3 |
| FR-12 | 선택형 Add-on 수명주기 | Q62, Q63, Q64, Q65, Q66, Q67, Q68, Q69, Q70, Q71, Q72 | 11 |
| NFR-01 | 아키텍처·의존성·구현성 | Q73, Q74, Q75, Q77 | 4 |
| NFR-02 | 로깅·진단 가능성 | Q58, Q59 | 2 |
| NFR-03 | 품질·CI·장애 테스트 | Q60, Q61, Q78 | 3 |
| NFR-04 | 공급망·라이선스·릴리스·지원 | Q79, Q80, Q81, Q82, Q83, Q84 | 6 |
| **합계** | **12 FR + 4 NFR** | **Q01~Q84 정확히 1회** | **84** |

## 2. 기능 요구사항 — 상세 명세

### FR-01. 지원 대상·토폴로지

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q01 | 개인 연구자와 일반 개발자가 GitHub에서 사용할 수 있도록 공개하고, 사용·수정·테스트 절차를 제공한다. |
| Q02 | Ubuntu LTS, Debian, RHEL 계열을 최종 지원 대상으로 삼되 배포판·버전·아키텍처별로 검증된 조합만 공식 지원한다. |
| Q03 | Bare Metal, 일반 VM, 기존 Public Cloud VM을 대상으로 한다. 하부 인프라 자동 생성은 포함하지 않는다. |
| Q04 | Single-node와 단일 Control Plane + 하나 이상의 Worker로 구성된 Multi-node를 지원한다. HA Control Plane은 현재 기본 범위에서 제외한다. |
| Q09 | Single-node에서는 Control Plane의 일반 Workload 스케줄링을 기본 허용하고 명시적으로 차단하는 모드를 제공한다. |
| Q11 | Cloud VM에 대한 게스트 OS 내부 설치를 수행하며 VPC, Security Group, CCM/CSI와 같은 외부 클라우드 인프라 변경을 자동 약속하지 않는다. |

**인수 기준 AT-01:** 인벤토리의 승인된 노드에만 구성되고, Single-node와 다중 Worker 모드를 검증한다. 미검증 플랫폼은 명시적으로 `UNSUPPORTED` 처리한다.

### FR-02. 버전 선택·Container Runtime

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q06 | 기본 설치는 공식 지원 중이고 호환성 테스트를 통과한 Kubernetes 패치 버전을 선택한다. 사용자가 명시한 버전도 검증 후 허용한다. |
| Q07 | EOL Kubernetes는 기본 거부하며 `--allow-eol` 지정 시 별도 경고·아티팩트 가용성 검사를 거쳐 연구용으로 허용한다. |
| Q08 | 컨테이너 실행 환경은 containerd로 고정한다. 기존 호환 containerd는 재사용하고, 미설치 시 검증된 버전만 설치한다. Docker 존재만으로 무단 제거하지 않는다. |

**AT-02:** Kubernetes/Calico/containerd/OS 버전 결정을 잠금 파일에 기록하고 CRI 응답·cgroup 정합성을 검증한다. 호환 불가 버전은 설치 전에 차단한다.

### FR-03. 호스트 사전 설정

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q21 | Swap의 실제 활성 경로를 탐지하여 기존 설정을 백업하고 재부팅 후에도 비활성화되도록 설정한다. |
| Q22 | Kernel Module, sysctl, cgroup을 검증하고 필요한 항목만 변경하며 변경 전후 값 및 소유권을 기록한다. |
| Q23 | SELinux와 NetworkManager는 유지하고 Calico 호환 예외만 적용한다. 활성 firewalld 등 미검증 충돌 조건이면 중단한다. |
| Q24 | DNS 해석, NTP/시계 동기화 및 서비스 접근성을 점검하고 해결 불가 시 변경 전에 중단한다. |

**AT-03:** 적용 전후 값이 기록되고, 기존 시스템 설정이 임의로 삭제되지 않는다. 재부팅 뒤 필수 Kernel/sysctl/Swap 정책을 재검증한다.

### FR-04. Kubernetes 핵심 구성

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q25 | 선택한 Kubernetes 버전의 kubeadm API에 맞는 YAML을 자동 생성하고 스키마 및 교차 설정을 검증한다. |
| Q26 | Node IP를 검증해 API Endpoint를 선택하며, 승인된 FQDN/IP Override와 API Server 인증서 SAN을 지원한다. |
| Q27 | kubeadm이 관리하는 Local etcd를 사용한다. External etcd와 HA Control Plane은 현재 범위 밖이다. |
| Q29 | kubeadm 기본 PKI 생성·갱신·만료 규칙을 준수하며 개인키를 로그에 기록하지 않는다. |
| Q30 | kube-proxy는 iptables 기본, 검증된 Calico/Kubernetes 조합에서만 nftables 선택 지원한다. |
| Q31 | kubeadm CoreDNS 기본 설치를 유지하며 업스트림 DNS 검증과 선택적 Override를 지원한다. |
| Q32 | kubelet CRI/cgroup을 검증하고 maxPods, systemReserved, kubeReserved 등 노드별 값을 선택적으로 적용한다. |
| Q33 | 공식 이미지 Registry 기본값, 인증서가 검증된 Mirror와 Proxy 선택 지원, 이미지 및 Chart 소스 추적을 제공한다. |

**AT-04:** kubeadm Configuration 스키마 검증, Control Plane 정상·etcd 건강 상태, kubelet/CRI 및 Service/DNS 확인을 통과해야 한다.

### FR-05. Calico 및 네트워크

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q13 | Calico는 Operator와 고정 Manifest 설치 방식을 지원하며 Operator를 기본으로 한다. 기존 설치 방식을 자동 전환하지 않는다. |
| Q14 | Pod/Service CIDR 후보를 자동 계산하고 전체 노드와 신고된 외부 네트워크 CIDR·Route의 충돌을 검증한다. 미확인 중요 경로가 있으면 중단한다. |
| Q15 | IPv4 VXLAN Always를 기본으로 하고 검증된 IP-in-IP/BGP 등 선택지를 제공한다. |
| Q16 | Node IP/NIC는 Control Plane 도달 경로와 노드 간 연결성을 검증하여 선택하고 모호하면 중단한다. |
| Q17 | 첫 구현은 IPv4 전용이며 IPv6 및 Dual-Stack은 후속 범위로 둔다. |
| Q18 | Calico IPv4 IPAM 블록은 /26을 기본으로 하되 초기 구성 시 사용자 Override를 허용한다. 기존 클러스터에서 위험한 자동 블록 변경은 금지한다. |
| Q19 | NIC·실제 경로·캡슐화 오버헤드를 검증해 MTU를 도출하고, 사용자 Override 시에도 연결성 테스트를 수행한다. |
| Q20 | 방화벽은 승인된 호스트 규칙만 최소 변경하고 변경 전후를 기록한다. 클라우드 보안그룹을 변경했다고 가정하지 않는다. |

**AT-05:** 같은 노드/다른 노드 Pod-to-Pod, ClusterIP, DNS, NetworkPolicy 검사에 성공해야 한다. 실제 경로 충돌이나 방화벽 간섭 시 `BLOCKED` 처리한다.

### FR-06. 안전한 원격·무인 오케스트레이션

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q05 | 사전에 승인된 정책과 설정을 입력받아 비대화형 무인 설치를 수행한다. 확인할 수 없는 중요 항목을 임의 추측하지 않는다. |
| Q10 | 중앙 제어 노드에서 Inventory에 지정된 호스트만 SSH를 통해 설치하고 Worker Join을 자동화한다. |
| Q12 | 위험이 낮은 기본 설정만 자동 적용하고 중대한 불확실성·충돌이 있으면 변경 전 차단한다. |
| Q36 | SSH Key/Agent 기반 비밀번호 입력 없는 접근을 기본으로 한다. |
| Q37 | known_hosts 또는 승인된 지문으로 Host Key를 엄격 검증하고 새 호스트 키를 무조건 신뢰하지 않는다. |
| Q38 | 일반 SSH 계정과 사전 승인된 비대화형 sudo를 사용하며 root 직접 SSH 로그인을 요구하지 않는다. |
| Q40 | Inventory에 선언된 호스트만 접근·변경하고 해당 노드의 환경 정보를 자동 탐지한다. |
| Q43 | 자동 Preflight → 실행 계획 검증 → 사전 정책 일치 확인 → 추가 질문 없는 Apply를 수행한다. |
| Q44 | SSH Agent, Ansible Vault 또는 Secret Manager로 자격 증명을 다루고 토큰·비밀번호를 로그/일반 설정에 저장하지 않는다. |
| Q45 | 단기 Bootstrap Token을 생성하고 Kubernetes CA 공개키 해시 검증을 유지하며 완료 후 불필요한 토큰을 폐기한다. |
| Q46 | 모든 노드를 Preflight한 뒤 Control Plane을 초기화하고 상태 게이트를 통과하면 Worker를 제한된 동시성으로 Join한다. |

**AT-06:** 사전 승인·키·sudo·신원 검증이 끝난 환경에서 입력 없이 설치하고, 미등록 노드·키 불일치·CA 미검증·불완전 계획을 차단한다.

### FR-07. CLI·설정 스키마

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q39 | `inventory.yaml`(호스트·역할·접속)과 `cluster.yaml`(클러스터 정책)을 분리하고 둘 모두 스키마로 검증한다. |
| Q41 | `plan`, `apply`, `validate`, `status` CLI를 제공하고 복구·제거·Add-on 명령을 확장한다. |
| Q42 | 강제 안전 제약이 최종 검증을 지배하며 설정 병합은 CLI > YAML > 검증된 탐지값 > 기본값 순으로 수행한다. 충돌을 조용히 덮어쓰지 않는다. |
| Q76 | 설정 파일의 `schemaVersion`을 선언하고 버전별 유효성 검증 및 명시적 Migration 경로를 제공한다. |

**AT-07:** 잘못된 YAML, 충돌 노드 역할, 지원하지 않는 스키마를 거부하고 계획의 설정 출처와 변경 내용을 보여 준다.

### FR-08. etcd 백업·관리자 접근·감사

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q28 | 검증 완료 후 etcd 스냅샷을 생성·무결성 점검하고 암호화·접근 제한 저장소에 보관한다. 스냅샷 생성과 실제 복구 검증은 구분한다. |
| Q34 | 관리자 kubeconfig는 Control Plane과 명시적으로 승인된 관리 호스트에만 배포한다. |
| Q35 | API Server Audit을 선택적으로 활성화하고 로그 크기·보존·개인정보 노출 정책을 검증한다. |

**AT-08:** 스냅샷의 상태·소유권·접근권한을 확인하고, 인증 정보가 비승인 호스트 또는 일반 로그에 존재하지 않음을 검사한다.

### FR-09. 설치 후 기능 검증

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q48 | Node·Control Plane·Calico·DNS·Service를 기능 수준에서 검증한다. |
| Q49 | 전용 임시 Pod로 노드 내부 및 노드 간 통신, Service, DNS를 실제 테스트하고 자원을 정리한다. |
| Q50 | 단계별 타임아웃과 횟수가 제한된 재시도를 적용하고 원인 및 상태를 보고한다. |
| Q51 | 격리된 테스트 Namespace에서 NetworkPolicy Allow/Deny를 시험하고 전역 정책 충돌을 먼저 검증한다. |

**AT-09:** 각 검사를 PASS/FAIL/SKIPPED/NOT_APPLICABLE/INCONCLUSIVE로 구분하며, 미실행 검증을 성공으로 처리하지 않는다.

### FR-10. 상태·Drift·복구

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q47 | 실제 상태·변경 기록을 확인한 후 안전한 단계만 재시도하고 파괴적 복구는 중단한다. |
| Q52 | 중앙 실행 상태와 노드별 로컬 상태를 저장하며 Kubernetes/OS의 관측 상태와 교차 검증한다. |
| Q53 | Desired/Observed 차이를 검사하고 승인된 안전 변경만 적용한다. |
| Q54 | 중단 후 재실행 시 제한적 자동 복구를 지원하고 etcd·CNI·기존 데이터 변경은 별도 절차로 보호한다. |

**AT-10:** 중간 중단·중앙 상태 기록 손실·네트워크 단절 후 다시 실행해도 기존 정상 노드와 사용자 데이터를 훼손하지 않는다.

### FR-11. 안전한 노드·클러스터 제거

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q55 | Worker 단위 제거와 전체 클러스터 제거를 별도 명령으로 지원한다. |
| Q56 | 명시적 대상 지문·제거 범위·영향 분석·사전 승인된 파괴 정책이 확인된 경우에만 실행한다. |
| Q57 | CREATED_BY_TOOL, MODIFIED_BY_TOOL, PRE_EXISTING, SHARED, UNKNOWN 소유권을 구분하고 변경·소유 항목만 선택적으로 정리한다. |

**AT-11:** 기존 containerd·사용자 kubeconfig·PV/PVC·공유 방화벽 규칙을 무단 삭제하지 않는다. `kubeadm reset`만으로 완전 원상복구가 되었다고 주장하지 않는다.

### FR-12. 선택형 Add-on 수명주기

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q62 | Kubernetes 핵심 구성 외 Add-on은 기본 비활성, 명시적 정책을 통해서만 설치한다. |
| Q63 | Helm Chart 버전과 Values를 고정·검증하며 Chart/CRD 소유권을 추적한다. |
| Q64 | Metrics Server를 선택 설치하고 Metrics API 및 `kubectl top` 동작을 확인한다. |
| Q65 | Kubelet Serving TLS 및 Aggregation API에서 인증서 검증을 유지하며 검증 불가 시 해당 Add-on 설치 실패로 처리한다. |
| Q66 | 검증된 Local Storage 또는 CSI Provider를 선택 지원하되 기본 미설치한다. |
| Q67 | 사용자가 지정한 StorageClass를 검증한 후에만 기본값으로 지정하고 기존 PVC 영향 평가를 수행한다. |
| Q68 | MetalLB 등을 검증된 Underlay/L2/BGP 환경에서만 선택 지원한다. |
| Q69 | Gateway API를 우선 지원하고 검증된 별도의 Ingress Controller도 선택 지원한다. Gateway CRD뿐 아니라 Controller와 실제 트래픽까지 검증한다. |
| Q70 | cert-manager 등 인증서 자동화 도구를 선택 설치하고 발급자·도메인 선행 조건을 별도 검증한다. |
| Q71 | Prometheus/Grafana 등을 자원·스토리지 조건에 맞춰 선택 설치한다. |
| Q72 | 설치 이력 기반 승인된 Add-on Upgrade/Rollback을 지원하되 CRD·PV·외부 데이터의 완전 복원을 약속하지 않는다. |

**AT-12:** 기본 설치에서 선택되지 않은 Add-on이 배포되지 않는다. 선택된 Add-on은 의존성·기능 검사에 성공해야 하며 실패 상태는 핵심 클러스터 상태와 구분한다.

## 3. 비기능 요구사항 — 상세 명세

### NFR-01. 아키텍처·의존성·구현성

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q73 | Python CLI + Ansible 원격 자동화 + 최소 Bash Bootstrap으로 구현한다. |
| Q74 | Core Engine, OS Adapter, Kubernetes, Calico, Add-on 모듈을 분리하고 안정적 인터페이스로 연결한다. |
| Q75 | 검증된 의존성 버전 Lockfile·격리된 실행 환경·자동 Bootstrap을 사용하며 시스템 전역의 무분별한 업데이트를 금지한다. |
| Q77 | CLI/Ansible/Adapters/Schemas/Tests/Docs를 포함한 단일 Monorepo를 사용한다. |

**AT-13:** 모듈 경계별 Unit Test, 잠금 의존성 재설치, 서로 다른 OS Adapter 선택 테스트를 통과해야 한다.

### NFR-02. 로깅·진단 가능성

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q58 | 읽기 쉬운 콘솔 로그와 구조화 JSON 로그, 보존·회전 정책을 제공한다. |
| Q59 | 노드·서비스·네트워크를 조사하는 진단 보고서를 만들되 민감정보 제거 및 로컬 권한 보호를 적용한다. |

**AT-14:** 실행 ID·노드·단계·시간·종료 결과를 추적하고, 토큰·키·패스워드가 로그에 기록되지 않는지 자동 검사한다.

### NFR-03. 품질·CI·장애 테스트

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q60 | Lint·Schema·Unit·지원 OS별 VM 통합 테스트를 단계별 CI에서 수행한다. |
| Q61 | 재부팅·작업 중단·Join 실패·네트워크 장애를 별도 격리된 통합 테스트에서 검증한다. |
| Q78 | PR에는 정적 검사와 Unit/Schema를, 별도 워크플로에는 VM/장애 통합 테스트를, Release에는 증빙 기반 검증을 적용한다. |

**AT-15:** PR 검증, 지정된 VM 통합 테스트, 실패 주입, 정리 테스트 및 재실행 테스트가 릴리스 게이트를 만족해야 한다.

### NFR-04. 공급망·라이선스·릴리스·지원

| 원본 ID | 규범적 하위 명세 |
|---|---|
| Q79 | 외부 의존성을 버전·해시로 고정하고 보안 스캔, SBOM, 릴리스 서명 또는 Build Provenance 증명을 제공한다. |
| Q80 | 프로젝트 자체 소스코드는 Apache License 2.0으로 공개하며 번들 의존성 라이선스를 별도 검토한다. |
| Q81 | 개발 중 0.x에서 시작하고 안정적 API/설정 계약 검증 뒤 SemVer 1.0+를 선언한다. |
| Q82 | 실제 통합 테스트를 통과한 OS·아키텍처·Kubernetes·containerd·Calico 조합만 공식 지원 목록에 등록한다. |
| Q83 | Stable Release와 RC/Pre-release를 구분하고 명시적 버전 고정 설치를 지원한다. |
| Q84 | README, 설치 가이드, 설정 레퍼런스, 문제 해결, CONTRIBUTING, SECURITY, CHANGELOG, Issue 템플릿을 제공한다. |

**AT-16:** 릴리스마다 지원 매트릭스·테스트 증빙·SBOM·검증 가능한 해시/증명·라이선스·변경 내역이 존재해야 한다.

## 4. 통합 제약 조건·충돌 해결

다음 C-번호는 앞선 단계에서 제안된 CON-001~CON-053을 중복 없는 집합으로 정규화한 **안전 규칙 초안**이다. 기술적으로 검증된 기본 불변조건을 우선 적용하며, 나머지는 테스트를 통해 구체화한다.

| 규칙 | 적용 제약 및 원본 관련 ID | 차단/처리 조건 |
|---|---|---|
| C-01 | 지원 범위·버전 (Q02, Q06, Q07, Q82) | EOL 기본 거부, 미검증 조합은 지원 불가 |
| C-02 | 기존 환경 보존 (Q08, Q12, Q22, Q57) | Docker/containerd/설정/공유 데이터 무단 삭제 금지 |
| C-03 | Calico 이중 배포 방지 (Q13, Q30) | 기존 CNI 또는 관리 방식과 충돌하면 중단 |
| C-04 | 네트워크 일관성 (Q14~Q20) | 충돌 CIDR, 모호한 Node IP, 확인 불가 MTU/방화벽은 중단 |
| C-05 | SELinux/NetworkManager/firewalld (Q20, Q23) | 보안 수준 무단 저하 금지; Calico 미검증 간섭 환경은 차단 |
| C-06 | kubeadm/PKI/DNS (Q25, Q26, Q29, Q31, Q32) | 스키마·SAN·CRI·DNS 루프 등 불일치 차단 |
| C-07 | SSH/Bootstrap 비밀정보 (Q34, Q36~Q45) | 신뢰되지 않은 Host Key, 무검증 CA, 비밀정보 로그 기록 금지 |
| C-08 | 계획 불변성 (Q39~Q43) | CLI/YAML 병합 결과를 검증, Apply 직전 중요 환경 재검증 |
| C-09 | 검증 정확성 (Q48~Q51) | 테스트 미실행 또는 단일 노드에서 교차 노드 성공 주장 금지 |
| C-10 | 재시도·복원 (Q28, Q47, Q52~Q54) | 상태 기록만으로 성공 간주 금지; 파괴적 자동 Reset 금지 |
| C-11 | 제거 보호 (Q55~Q57) | Drain/PDB/PV/PVC·소유권 확인, 명시적 파괴 승인 필요 |
| C-12 | Add-on 생명주기 (Q62~Q72) | TLS 우회/임의 StorageClass/미검증 MetalLB/CRD 자동 롤백 금지 |
| C-13 | 릴리스·진단 (Q58~Q61, Q78~Q84) | 테스트 없는 지원 선언, 인증정보 누출, 무검증 릴리스 금지 |

**핵심 상충 사항:**

1. **완전 무인 설치 ≠ 불확실성 자동 추측.** 인벤토리·정책·권한을 먼저 준비하고 중대한 미확정 사항은 `BLOCKED`.
2. **‘최신 버전’ ≠ 실행마다 부동 버전.** 최초 호환 버전 선택 후 Lockfile과 아티팩트 해시 고정.
3. **방화벽 유지 vs Calico 간섭.** firewalld 활성 환경은 공식 권고와 충돌할 수 있으므로 검증된 예외가 없으면 중단; 무단 중지 금지.
4. **Calico MTU·CIDR 자동 선택 ≠ 외부 네트워크 전체 보증.** 검증 범위를 기록하고 외부 네트워크 정보를 확보하지 못하면 차단.
5. **Helm Rollback ≠ CRD/데이터 Rollback.** CRD 설치 방식별 Upgrade 정책 분리.
6. **원상복구 ≠ OS 전체 스냅샷 복원.** 도구 소유·변경 리소스만 조건부 복원.
7. **Metrics Server TLS 검증 유지.** Kubelet과 Aggregation API 양측 TLS 요구사항을 확인.
8. **Cloud VM Kubernetes 설치 ≠ Cloud LoadBalancer/CCM/CSI 자동 구성.** 외부 인프라 제어는 기본 범위 제외.

## 5. 데이터 계약 및 CLI 설계

### 5.1 입력·출력

- `inventory.yaml`: 노드 ID, SSH 호스트/IP·사용자·포트, 역할, 호스트 키 신뢰 정보(또는 안전한 참조), 노드 그룹
- `cluster.yaml`: `schemaVersion`, 클러스터 ID, Kubernetes·containerd 정책, API Endpoint, CIDR, Calico, Add-on, 파괴·검증 정책
- `versions.lock`: 정확한 버전, Registry/Chart/이미지 다이제스트, 사용한 호환성 규칙 버전
- `plan.json`: 변경 대상, 작업 단계, 적용 전 조건, 실행 계획 해시, TTL, 인벤토리·클러스터 지문
- `state/`: 중앙 작업 체크포인트, 노드별 최소 상태/소유권 기록, 실제 상태 조회 결과
- `reports/`: 검증 결과, 비밀정보 마스킹 로그, 실패·중단 이유

### 5.2 CLI 계약(설계 목표; 아직 실제 구현 명령이 아님)

```bash
kauto plan --inventory inventory.yaml --config cluster.yaml --out plan.json
kauto apply --plan plan.json --unattended
kauto validate --inventory inventory.yaml --config cluster.yaml
kauto status --inventory inventory.yaml
kauto drift --inventory inventory.yaml --config cluster.yaml
kauto remove-worker --node worker-01 --approved-plan removal.json
kauto destroy --approved-plan destroy.json
kauto addon plan --name metrics-server --config cluster.yaml
```

`plan`은 기본적으로 호스트 상태를 변경하지 않는다. `apply`는 계획 지문·대상 신원·중요 환경을 재검사한다. `destroy`는 사전에 승인된 명시적인 대상과 정책 없이는 무인 모드에서도 실행되지 않는다. 예시 CLI 이름 `kauto`는 설계 가칭이다.

### 5.3 실행 상태 모델

- 실행 결과: `SUCCEEDED`, `PARTIALLY_SUCCEEDED`, `FAILED`, `BLOCKED`, `INTERRUPTED`, `UNKNOWN`
- 개별 검사: `PASS`, `FAIL`, `SKIPPED`, `NOT_APPLICABLE`, `INCONCLUSIVE`
- 노드 단계: `DISCOVERED`, `PREFLIGHT_PASSED`, `PREPARED`, `JOINED`, `HEALTHY`, `DEGRADED`, `REMOVAL_PENDING`, `REMOVED`
- 기록 신뢰성: `desired`, `execution`, `observed` 상태를 구분하여 관측 상태로 최종 확인
- 같은 클러스터에 대한 병행 Apply를 막을 수 있는 잠금/Lease 정책과 충돌 감지를 설계한다.

## 6. 인수 테스트 사양 (게이트)

| 테스트 | 상위 요구사항 | 성공 조건(간략) |
|---|---|---|
| AT-01 | FR-01 | 대상·역할·환경 인식, 비지원 조합 거부 |
| AT-02 | FR-02 | 버전 Lock 및 CRI/cgroup 정상, EOL 정책 검증 |
| AT-03 | FR-03 | Swap/Kernel/sysctl의 최소 변경과 재부팅 후 상태 검증 |
| AT-04 | FR-04 | kubeadm Config 유효, Control Plane/etcd/CoreDNS 정상 |
| AT-05 | FR-05 | Pod/Service/DNS/NetworkPolicy 통신 검증 |
| AT-06 | FR-06 | SSH·sudo·Host Key·CA 검증 및 단계적 무인 배포 |
| AT-07 | FR-07 | 스키마·우선순위·Plan 변경 탐지·CLI 동작 |
| AT-08 | FR-08 | 백업 권한·무결성, kubeconfig 배포 범위, Audit 정책 |
| AT-09 | FR-09 | PASS/FAIL/SKIP 기준 준수, 격리 테스트 정리 |
| AT-10 | FR-10 | 중단/재시도/Drift 감지 시 정상 자원 보존 |
| AT-11 | FR-11 | Worker 안전 제거·소유권 기반 클러스터 정리 |
| AT-12 | FR-12 | Add-on 선택 활성, 의존성·TLS·자원·기능 검증 |
| AT-13 | NFR-01 | 모듈 테스트·Lockfile 재현·OS Adapter 교체 테스트 |
| AT-14 | NFR-02 | 구조화 로그·진단 보고서·비밀정보 마스킹 확인 |
| AT-15 | NFR-03 | PR·VM 설치·장애 주입·재부팅 CI 게이트 통과 |
| AT-16 | NFR-04 | Release 산출물·SBOM·증명·문서·지원 매트릭스 검증 |

## 7. MVP·Stable v1.0·후속 버전 범위

| 단계 | 구현 우선 범위 | 릴리스 게이트 |
|---|---|---|
| **MVP (0.x 초기)** | Ubuntu 22.04/24.04 LTS x86_64의 검증된 VM, 단일 Control Plane Single-node, containerd, kubeadm, Calico Operator, 필수 Preflight, 기본 CLI, 기능 검증 | 신선한 VM 설치·재실행·재부팅 검증. 실제 지원 선언은 테스트 통과 후 |
| **0.x 확장** | Ubuntu Multi-node SSH Inventory, 단계적 Worker Join, 상태·로그·진단·Drift 기초, 최소 위험 복구, 안전한 Worker 제거 | 적어도 1 CP + 2 Worker 테스트, 실패 주입, 소유권 보존 |
| **Stable 1.0 후보** | 명시한 공식 지원 조합에 대해 기능/안전/검증/문서/CI 계약 안정화. 검증된 선택형 Add-on은 지원 목록에 한정 | AT-01~AT-16 중 해당 릴리스 지원 범위의 MUST 테스트 통과. 미구현 프로젝트 로드맵 기능을 제품 지원으로 허위 표기 금지 |
| **후속 1.x+** | Debian·RHEL 별도 Adapter, Public Cloud VM 실증, 고급 nftables, 추가 Storage/MetalLB/Gateway/Monitoring, Add-on Upgrade/Rollback 성숙화 | OS·Kubernetes·Calico·Runtime별 독립 통합 테스트 통과 |

**중요:** Q02의 3계열 OS 및 Q03의 3종 인프라 지원은 최종 프로젝트 요구 범위이며, 최초 Stable 1.0 시점의 실제 공식 지원 대상은 릴리스 테스트로 결정한다. 구현하지 않은 기능은 지원하지 않는다고 명시한다.

## 8. Compatibility Matrix — 구조 및 현재 상태

**상태 값:** `PLANNED`(계획), `DOC_CANDIDATE`(문서상 후보), `TESTING`(실험 중), `VERIFIED`(통합 테스트 통과), `SUPPORTED`(릴리스에 포함), `BLOCKED`(지원 불가). **문서상 호환 가능 ≠ 실측 설치 성공.**

| OS/인프라 후보 | Kubernetes 후보 정책 | Runtime/CNI 후보 | 현재 상태 |
|---|---|---|---|
| Ubuntu 22.04 LTS amd64 / VM | 공식 지원 중인 패치 버전 | 검증된 containerd + Calico Operator | PLANNED |
| Ubuntu 24.04 LTS amd64 / VM | 공식 지원 중인 패치 버전 | 검증된 containerd + Calico Operator | PLANNED |
| Ubuntu 22.04/24.04 / Bare Metal | 위 조합 + NIC/방화벽 별도 확인 | 동일 | PLANNED |
| Ubuntu LTS / Proxmox·OpenStack VM | 위 조합 + Overlay MTU·연결성 확인 | 동일 | PLANNED |
| Debian 선택 릴리스 / VM | 해당 OS 테스트 후 확정 | 해당 Adapter 별도 검증 | PLANNED |
| RHEL/Rocky/Alma 선택 릴리스 / VM | 해당 OS 테스트 후 확정 | SELinux·firewalld 검증 필요 | PLANNED |
| AWS·Azure·GCP의 기존 Linux VM | 지원 OS와 외부 방화벽·사설망 검사 후 확정 | Cloud LB/CSI 자동 지원 제외 | PLANNED |

2026-10-10 기준 Kubernetes 공식 릴리스 페이지는 1.37·1.36·1.35를 최신 세 유지보수 Minor로 명시한다. Calico 3.33 공식 문서는 1.35~1.37을 테스트 대상으로 표기한다. 이 조합은 **초기 후보**이지 본 프로젝트의 공식 검증 결과가 아니다. EOL 1.29는 `--allow-eol` 레거시 연구 전용으로 별도 시험한다.

Matrix의 최종 키는 `OS ID/version/arch + kernel + infra/network + K8s patch + kubeadm config API + containerd version/CRI + Calico version/install method/dataplane + proxy mode + addons`로 구성한다. 각 행에는 검증 날짜·실행 환경·테스트 로그·실패 코드·지원 종료일을 연결한다.

## 9. 소프트웨어 아키텍처

```text
User / CI
   |
Bootstrap (Bash: verified release + isolated environment)
   |
Python CLI (plan/apply/validate/status/drift/remove)
   |
Config Resolver -- Policy/Compatibility Engine -- Version Lock
   |
Discovery & Preflight -- Inventory/Trust & Secrets -- Plan Snapshot
   |
State/Ownership Store <-- Orchestrator --> Ansible Executor
                               |                 |
                          OS Adapters       SSH + sudo
                               |
                    containerd / kubeadm / Calico
                               |
                         Add-on Manager
                               |
                 Health / Drift / Cleanup / Reports
```

**원칙:** Python은 정책과 상태의 단일 소유자, Ansible은 선언된 실행 계획에 기반한 원격 작업 담당자다. OS별 차이는 Adapter가 흡수하고, Ansible Check Mode는 Plan의 유일한 근거로 사용하지 않는다. 파괴적 단계는 일반 설치 단계와 별도의 승인을 요구한다.

### GitHub Monorepo 권장 구조

```text
kubernetes-installer/
  LICENSE
  README.md
  SECURITY.md
  CONTRIBUTING.md
  CHANGELOG.md
  pyproject.toml
  requirements.lock
  bootstrap/install.sh
  src/kauto/cli/
  src/kauto/core/       # config, policy, planner, state, ownership
  src/kauto/adapters/   # ubuntu, debian, rhel
  src/kauto/modules/    # runtime, kubeadm, calico, addons
  ansible/playbooks/
  ansible/roles/
  schemas/
  compatibility/
  configs/examples/
  tests/unit/
  tests/integration/
  tests/fault_injection/
  docs/SRS.md
  docs/configuration.md
  docs/installation.md
  docs/troubleshooting.md
  docs/architecture.md
  .github/workflows/pr.yml
  .github/workflows/integration.yml
  .github/workflows/release.yml
  .github/ISSUE_TEMPLATE/
```

## 10. 출시 이후 작업 계획 — 우선순위

1. **ADR 작성:** Python↔Ansible 경계, OS Adapter 계약, 상태 저장 방식, 비밀정보 전략, 실패/복구 범위 결정.
2. **Schema:** `inventory.yaml`, `cluster.yaml`, `versions.lock`, `plan.json`, `state`의 타입과 버전·마이그레이션 테스트 설계.
3. **Compatibility Matrix:** Ubuntu 22.04/24.04 등 실제 VM의 OS/Kernel/Calico/Runtime/패치 버전 수집, 공식 문서 확인, Docker 비삭제 원칙 검증.
4. **Proof of Concept:** Ubuntu 22.04 VM 단일 노드에서 Plan→Apply→Validate→재부팅→재실행을 끝까지 검증.
5. **Multi-node:** 인벤토리 + SSH + 엄격 호스트 키 검증, Join Token 회전 및 실패 재개 테스트.
6. **안전한 Cleanup:** 리소스 소유권·Drain·공유 자원 의존성·파괴 승인 테스트.
7. **GitHub 품질 게이트:** PR 검사, 격리 VM 통합 시험, SBOM·프로비넌스/서명, 문서·릴리스 게이트 추가.
8. **지원 범위 확대:** 통합 테스트 증빙이 확보될 때만 Debian·RHEL·Cloud VM에 `SUPPORTED` 부여.

## 11. 공식 근거 문서(지속 갱신 대상)

- Kubernetes Releases: https://kubernetes.io/releases/
- Kubernetes kubeadm 설치: https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/
- kubeadm Configuration API: https://kubernetes.io/docs/reference/config-api/kubeadm-config.v1beta4/
- Container Runtimes: https://kubernetes.io/docs/setup/production-environment/container-runtimes/
- kubeadm reset 한계: https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-reset/
- Calico System Requirements: https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements
- Helm CRD Lifecycle: https://helm.sh/docs/chart_best_practices/custom_resource_definitions/
- Metrics Server Security/Requirements: https://github.com/kubernetes-sigs/metrics-server/blob/master/FAQ.md
- Gateway API Getting Started: https://gateway-api.sigs.k8s.io/guides/getting-started/introduction/
- MetalLB Cloud Compatibility: https://metallb.io/installation/clouds/
- StorageClass: https://kubernetes.io/docs/concepts/storage/storage-classes/
- Ansible Check Mode: https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_checkmode.html
- GitHub Artifact Attestations: https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations
- Semantic Versioning: https://semver.org/
- Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0

---

**최종 문서 판정:** 요구사항 수집 8/8 완료, 84개 선택을 16개 상위 명세로 누락·중복 없는 일대일 주 매핑 완료. **구현 및 실환경 검증은 아직 수행되지 않았다.** 이 문서는 설계 베이스라인이며 코드·테스트·호환성 증빙이 확보되면서 버전 관리 하에 정제한다.
