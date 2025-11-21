from flask import Flask, request, jsonify, render_template
from Crypto.Util import number
import math

app = Flask(__name__)

# ==========================================
# RSA 키 생성 모듈 (RSA Key Generation Module)
# ==========================================
def generate_key_pair():
    """
    서버 구동 시 교육용 시연을 위한 8비트 RSA 키 쌍을 생성합니다.
    반환값: (N, e, d)
    """
    print("[시스템] RSA 키 생성 초기화 중...")
    
    # 1. 서로 다른 두 소수 p, q 생성
    # (교육용 시각화를 위해 8비트 크기의 작은 소수 사용)
    p = number.getPrime(8)
    q = number.getPrime(8)
    while p == q:
        q = number.getPrime(8)

    # 2. N (모듈러스) 및 Phi(N) 계산
    N = p * q
    phi_n = (p - 1) * (q - 1)

    # 3. 공개키 지수 e 선택
    e = 65537
    # e와 phi_n이 서로소(gcd=1)가 아니면 다른 값으로 조정
    if math.gcd(e, phi_n) != 1: e = 17
    if math.gcd(e, phi_n) != 1: e = 3
        
    # 4. 개인키 지수 d 계산 (확장 유클리드 알고리즘)
    # d * e ≡ 1 (mod phi_n)을 만족하는 d 도출
    d = pow(e, -1, phi_n)
    
    print(f"[시스템] 키 생성 완료: N={N}, e={e}, d={d}")
    return (N, e, d)

# 서버 시작 시 전역 변수에 키 할당
SERVER_N, SERVER_E, SERVER_D = generate_key_pair()


# ==========================================
# API 엔드포인트 (API Endpoints)
# ==========================================

@app.route('/')
def index():
    return render_template(
        'index.html',
        n=SERVER_N,
        e=SERVER_E,
        d=SERVER_D
    )

@app.route('/api/challenge', methods=['GET'])
def get_challenge():
    # 시연을 위해 고정된 메시지(99)를 반환합니다.
    # 실제 환경에서는 랜덤한 난수(Nonce)를 사용해야 합니다.
    return jsonify({'message': 99})

@app.route('/api/verify', methods=['POST'])
def verify_signature():
    try:
        data = request.get_json()
        signature = data.get('signature')
        original_message = data.get('original_message')

        # [서버 검증 로직]
        # RSA 검증 공식: M' = S^e mod N
        # 파이썬의 pow(base, exp, mod)를 사용하여 모듈러 거듭제곱 수행
        decrypted_signature = pow(signature, SERVER_E, SERVER_N)
        
        print(f"[인증] 서명 검증 수행: 서명값({signature}) -> 복원값({decrypted_signature})")

        is_valid = (decrypted_signature == original_message)
        
        return jsonify({
            'valid': is_valid,
            'decrypted': decrypted_signature,
            'info': "검증 프로세스: M' = S^e mod N"
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(port=5000, debug=True)