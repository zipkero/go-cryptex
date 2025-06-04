## 개요

실제 HTTPS/TLS에서 사용되는 혼합 암호화(Hybrid Cryptography) 방식을 단순화하여 구현

### RSA 구현 표준

- Public Key: PKIX (.pem)
- Private Key: PKCS#8 (.pem)
- Data Encryption: RSA-OAEP + SHA-256
  - RSA-2048: ≤190 bytes
  - RSA-4096: ≤446 bytes
- Signature: RSA-PSS + SHA-256
- Key Size: 2048bit minimum

### AES 구현 표준

- Key Size: 256bit (32 bytes)
- Mode: CBC
- padding: PKCS#7
- IV: 128 bit random

### Hybrid 구현 표준

- Bulk Encryption: AES-256-CBC + PKCS#7
- Key Encryption: RSA-OAEP + SHA-256
- Digital Signature: RSA-PSS + SHA-256
- Random Generation: crypto/rand

## 프로젝트 구조

```text
go-cryptex/
├── README.md
├── go.mod
├── cmd/
│   ├── demo/
│   │   └── main.go
│   ├── client/
│   │   └── main.go
│   └── server/
│       └── main.go
├── pkg/
│   ├── asymmetric/            # 비대칭키 암호화
│   │   ├── keypair.go         # 키쌍 생성/관리
│   │   ├── encrypt.go         # RSA 암호화/복호화
│   │   └── signature.go       # 디지털 서명/검증
│   ├── symmetric/             # 대칭키 암호화
│   │   ├── aes.go             # AES 암호화/복호화
│   │   └── session.go         # 세션키 생성/관리
│   ├── hybrid/                # 혼합 암호화
│   │   ├── encrypt.go         # 암호화/복호화
│   │   ├── exchange.go        # 키 교환 프로토콜
│   │   ├── session.go         # 세션 키 생성/관리
│   │   └── types.go           # 암호화 구조체 정의
│   └── utils/
│       ├── encoding.go        # Base64, Hex 인코딩
│       └── random.go          # 안전한 랜덤 생성
└── internal/ 
    ├── config/
    │   └── config.go
    └── errors/
        └── errors.go
```

### 대칭키 암호화

- [x] 세션키 생성

### 비대칭키 암호화

- [x] 키쌍 생성 (공개키/개인키)
- [x] 공개키로 암호화, 개인키로 복호화
- [x] 디지털 서명 및 검증

### 혼합형 암호화

- [ ] 세션 키 생성
- [ ] 비대칭키로 세션키 안전 전송
- [ ] 대칭키로 실제 데이터 암호화
- [ ] 디지털 서명과 검증 통합
- [ ] 하이브리드 메시지 구조체 정의
