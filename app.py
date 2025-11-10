from flask import Flask, request, jsonify, render_template
from Crypto.Util import number # (1) 랜덤 소수를 찾기 위해 import
import math # (2) 최대공약수(gcd) 계산을 위해 import

app = Flask(__name__)

# --- (3) 랜덤 키 생성을 위한 함수 ---
def generate_keys():
    """서버 실행 시 작은 랜덤 RSA 키 쌍을 생성합니다."""
    print("🔑 새로운 랜덤 키를 생성합니다...")
    
    # 1. 100~255 사이의 랜덤 소수 p, q를 찾음 (8비트 소수)
    p = number.getPrime(8)
    q = number.getPrime(8)
    while p == q: # p와 q가 다를 때까지 다시 뽑기
        q = number.getPrime(8)

    # 2. N (공용 계산기)
    N = p * q
    # 3. Phi(N) (마법의 시계)
    phi_n = (p - 1) * (q - 1)

    # 4. e (공개키) - 65537을 시도, 안되면 17, 3 순으로 시도
    e = 65537 # (자주 쓰는 e 값)
    if math.gcd(e, phi_n) != 1:
        e = 17
    if math.gcd(e, phi_n) != 1:
        e = 3
        
    # 5. d (개인키) - 확장 유클리드 알고리즘 사용
    # d = e^-1 mod phi_n
    d = pow(e, -1, phi_n)
    
    print(f"   (p={p}, q={q}) -> N={N}, Phi={phi_n}, e={e}, d={d}")
    return (N, e, d)

# --- (4) 서버가 켤 때 1회만 실행 ---
GLOBAL_N, GLOBAL_E, GLOBAL_D = generate_keys()

# --- (5) API 수정 ---

# API 1: 프론트엔드 보여주기 (키 전달)
@app.route('/')
def show_frontend():
    """index.html을 렌더링할 때 생성된 키 값을 전달합니다."""
    return render_template(
        'index.html',
        n_val = GLOBAL_N, # N 값을 'n_val'이라는 변수명으로 전달
        e_val = GLOBAL_E, # e 값을 'e_val'이라는 변수명으로 전달
        d_val = GLOBAL_D  # d 값을 'd_val'이라는 변수명으로 전달
    )

# API 2: 챌린지 (수정 없음)
@app.route('/get-challenge', methods=['GET'])
def get_challenge():
    message = 99
    # (주의: M=99가 N보다 크면 암호화가 깨집니다. 
    #  p,q가 작으므로 M도 작은 값(99)을 사용합니다.)
    print(f"✅ 서버: 프론트에게 M={message}를 보냈습니다.")
    return jsonify({'message': message})

# API 3: 서명 검증 (키 변수명 수정)
@app.route('/verify-signature', methods=['POST'])
def verify_signature():
    data = request.json
    original_message = data['original_message'] 
    signature_from_client = data['signature']

    print(f"🔁 서버: S={signature_from_client} 를 받았습니다. 검증 시작...")

    # (핵심 검증) 고정값이 아닌 '랜덤 생성된' 글로벌 키로 검증
    verified_message = pow(signature_from_client, GLOBAL_E, GLOBAL_N)
    print(f"   ...검증 결과(M'): {verified_message}")

    if original_message == verified_message:
        print("🎉 서버: 인증 성공!")
        return jsonify({'success': True, 'detail': f"검증 성공 (M'={verified_message})"})
    else:
        print("❌ 서버: 인증 실패!")
        return jsonify({'success': False, 'detail': f"검증 실패 (M'={verified_message})"})

# --- 서버 실행 ---
if __name__ == '__main__':
    print(f"🚀 RSA 랜덤 인증 서버를 시작합니다. http://127.0.0.1:5000/ 주소로 접속하세요.")
    app.run(port=5000, debug=True)
    app.run(port=5000, debug=True)

# === Deploy Trigger 1 ===