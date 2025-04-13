import sqlite3
import uuid
import re
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort, jsonify
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from functools import wraps
import bleach

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # 랜덤 시크릿 키 생성
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 세션 만료 시간 설정
app.config['SESSION_COOKIE_HTTPONLY'] = True  # HttpOnly 플래그 설정
app.config['SESSION_COOKIE_SECURE'] = False  # 개발 환경에서는 False, 운영 환경에서는 True로 설정
DATABASE = 'market.db'
socketio = SocketIO(app)

# 로그인 시도 횟수 제한을 위한 딕셔너리
login_attempts = {}
# 메시지 속도 제한을 위한 딕셔너리
message_rate_limit = {}

# CSRF 토큰 생성 함수
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

# CSRF 토큰 검증 함수
def validate_csrf_token():
    token = session.pop('_csrf_token', None)
    form_token = request.form.get('_csrf_token')
    return token is not None and token == form_token

# 템플릿에서 CSRF 토큰 사용할 수 있도록 전역 함수로 등록
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# 비밀번호 해싱 함수
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(8)
    # SHA-256 해시 함수 사용 (실제 운영 환경에서는 bcrypt 등 더 강력한 알고리즘 권장)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${hashed}"

# 비밀번호 검증 함수
def verify_password(stored_password, provided_password):
    salt, hashed = stored_password.split('$')
    return stored_password == hash_password(provided_password, salt)

# 입력값 검증 함수
def validate_username(username):
    # 사용자명은 알파벳, 숫자, 언더스코어만 허용하고 길이는 3-20자
    pattern = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    return bool(pattern.match(username))

def validate_password(password):
    # 비밀번호는 최소 8자 이상, 최대 50자 이하
    return 8 <= len(password) <= 50

def validate_price(price):
    # 가격은 숫자만 허용
    pattern = re.compile(r'^\d+$')
    return bool(pattern.match(price))

# XSS 방어를 위한 입력값 필터링 함수
def sanitize_input(text):
    if text is None:
        return None
    # HTML 태그 제거 및 이스케이프 처리
    return bleach.clean(text, tags=[], strip=True)

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 권한 확인 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT is_admin FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                is_admin BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'active',
                report_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                report_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 감사 로그 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 개인 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS private_message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 채팅방 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_room (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 채팅방 참가자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_participant (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(room_id, user_id)
            )
        """)
        db.commit()

# 감사 로그 기록 함수
def log_action(user_id, action, details=None):
    db = get_db()
    cursor = db.cursor()
    log_id = str(uuid.uuid4())
    ip_address = request.remote_addr
    cursor.execute(
        "INSERT INTO audit_log (id, user_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        (log_id, user_id, action, details, ip_address)
    )
    db.commit()

# 보안 헤더 설정
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# 에러 핸들러
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='페이지를 찾을 수 없습니다.'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error='서버 오류가 발생했습니다.'), 500

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('register'))
        
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        
        # 입력값 검증
        if not validate_username(username):
            flash('사용자명은 3-20자의 알파벳, 숫자, 언더스코어만 사용 가능합니다.')
            return redirect(url_for('register'))
        
        if not validate_password(password):
            flash('비밀번호는 8자 이상 50자 이하여야 합니다.')
            return redirect(url_for('register'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        
        # 비밀번호 해싱
        hashed_password = hash_password(password)
        
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        
        # 감사 로그 기록
        log_action(user_id, "REGISTER", f"New user registered: {username}")
        
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('login'))
        
        username = sanitize_input(request.form['username'])
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        
        # 사용자 조회
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        # 로그인 실패 처리
        if not user or not verify_password(user['password'], password):
            # 로그인 시도 횟수 증가
            ip = request.remote_addr
            login_attempts[ip] = login_attempts.get(ip, 0) + 1
            
            # 5회 이상 실패 시 지연 적용
            if login_attempts[ip] >= 5:
                flash('로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.')
                # 실제 운영 환경에서는 IP 기반 차단 또는 계정 잠금 로직 추가
                return redirect(url_for('login'))
            
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
        
        # 계정 잠금 확인
        if user['locked_until'] is not None:
            try:
                lock_time = datetime.fromisoformat(user['locked_until'])
                if lock_time > datetime.now():
                    flash('계정이 잠겨 있습니다. 나중에 다시 시도해주세요.')
                    return redirect(url_for('login'))
            except (ValueError, TypeError):
                pass  # 잘못된 형식인 경우 무시
        
        # 휴면 계정 확인
        if user['status'] == 'dormant':
            flash('계정이 휴면 상태입니다. 관리자에게 문의하세요.')
            return redirect(url_for('login'))
        
        # 로그인 성공 시 시도 횟수 초기화
        ip = request.remote_addr
        if ip in login_attempts:
            del login_attempts[ip]
        
        # 로그인 성공 처리
        session.clear()
        session['user_id'] = user['id']
        session['is_admin'] = bool(user['is_admin'])  # 관리자 여부 세션에 저장
        session.permanent = True  # 세션 만료 시간 적용
        
        # 감사 로그 기록
        log_action(user['id'], "LOGIN", f"User logged in: {username}")
        
        flash('로그인 성공!')
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    
    if user_id:
        # 감사 로그 기록
        log_action(user_id, "LOGOUT", "User logged out")
    
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 모든 상품 조회 (불량 상품 제외)
    cursor.execute("SELECT * FROM product WHERE status != 'blocked'")
    all_products = cursor.fetchall()
    
    # 읽지 않은 메시지 수 조회
    cursor.execute(
        "SELECT COUNT(*) as count FROM private_message WHERE receiver_id = ? AND is_read = 0",
        (session['user_id'],)
    )
    unread_count = cursor.fetchone()['count']
    
    return render_template('dashboard.html', products=all_products, user=current_user, unread_count=unread_count)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('profile'))
        
        bio = sanitize_input(request.form.get('bio', ''))
        
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        
        # 감사 로그 기록
        log_action(session['user_id'], "PROFILE_UPDATE", "User updated profile bio")
        
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    return render_template('profile.html', user=current_user)

# 비밀번호 변경 페이지
@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('change_password'))
        
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # 새 비밀번호 유효성 검사
        if not validate_password(new_password):
            flash('새 비밀번호는 8자 이상 50자 이하여야 합니다.')
            return redirect(url_for('change_password'))
        
        # 새 비밀번호 확인
        if new_password != confirm_password:
            flash('새 비밀번호와 확인 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('change_password'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 현재 사용자 비밀번호 확인
        cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        if not verify_password(user['password'], current_password):
            flash('현재 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('change_password'))
        
        # 새 비밀번호 해싱 및 업데이트
        hashed_password = hash_password(new_password)
        cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_password, session['user_id']))
        db.commit()
        
        # 감사 로그 기록
        log_action(session['user_id'], "PASSWORD_CHANGE", "User changed password")
        
        flash('비밀번호가 성공적으로 변경되었습니다.')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('new_product'))
        
        try:
            title = sanitize_input(request.form['title'])
            description = sanitize_input(request.form['description'])
            price = sanitize_input(request.form['price'], check_banned=False)  # 가격은 금지어 검사 제외
            
            # 입력값 검증
            if not title or len(title) < 2 or len(title) > 100:
                flash('제목은 2-100자 사이여야 합니다.')
                return redirect(url_for('new_product'))
            
            if not description or len(description) < 10 or len(description) > 1000:
                flash('설명은 10-1000자 사이여야 합니다.')
                return redirect(url_for('new_product'))
            
            if not validate_price(price):
                flash('가격은 숫자만 입력 가능합니다.')
                return redirect(url_for('new_product'))
            
            db = get_db()
            cursor = db.cursor()
            product_id = str(uuid.uuid4())
            
            cursor.execute(
                "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
                (product_id, title, description, price, session['user_id'])
            )
            db.commit()
            
            # 감사 로그 기록
            log_action(session['user_id'], "PRODUCT_CREATE", f"Created product: {title}")
            
            flash('상품이 등록되었습니다.')
            return redirect(url_for('dashboard'))
            
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('new_product'))
    
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 차단된 상품인 경우 접근 제한
    if product['status'] == 'blocked':
        flash('이 상품은 신고로 인해 차단되었습니다.')
        return redirect(url_for('dashboard'))
    
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    
    # 현재 로그인한 사용자인지 확인
    is_logged_in = 'user_id' in session
    is_seller = is_logged_in and session['user_id'] == product['seller_id']
    
    # 1대1 채팅방 ID 조회 (로그인한 경우)
    chat_room_id = None
    if is_logged_in and not is_seller:
        # 판매자와의 채팅방 확인
        cursor.execute("""
            SELECT cr.id FROM chat_room cr
            JOIN chat_participant cp1 ON cr.id = cp1.room_id
            JOIN chat_participant cp2 ON cr.id = cp2.room_id
            WHERE cp1.user_id = ? AND cp2.user_id = ?
            LIMIT 1
        """, (session['user_id'], product['seller_id']))
        
        chat_result = cursor.fetchone()
        if chat_result:
            chat_room_id = chat_result['id']
    
    return render_template('view_product.html', product=product, seller=seller, 
                          is_logged_in=is_logged_in, is_seller=is_seller, 
                          chat_room_id=chat_room_id)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('report'))
        
        target_id = sanitize_input(request.form['target_id'])
        target_type = sanitize_input(request.form['target_type'])
        reason = sanitize_input(request.form['reason'])
        
        # 입력값 검증
        if not target_id or len(target_id) < 5:
            flash('유효한 대상 ID를 입력해주세요.')
            return redirect(url_for('report'))
        
        if not target_type or target_type not in ['user', 'product']:
            flash('유효한 대상 유형을 선택해주세요.')
            return redirect(url_for('report'))
        
        if not reason or len(reason) < 10 or len(reason) > 500:
            flash('신고 사유는 10-500자 사이여야 합니다.')
            return redirect(url_for('report'))
        
        db = get_db()
        cursor = db.cursor()
        
        # 대상 존재 여부 확인
        if target_type == 'user':
            cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
        else:  # product
            cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
        
        target = cursor.fetchone()
        if not target:
            flash('존재하지 않는 대상입니다.')
            return redirect(url_for('report'))
        
        # 자기 자신 신고 방지
        if target_type == 'user' and target_id == session['user_id']:
            flash('자기 자신을 신고할 수 없습니다.')
            return redirect(url_for('report'))
        
        # 자신의 상품 신고 방지
        if target_type == 'product' and target['seller_id'] == session['user_id']:
            flash('자신의 상품을 신고할 수 없습니다.')
            return redirect(url_for('report'))
        
        # 신고 남용 방지: 동일 대상에 대한 신고 횟수 제한
        cursor.execute(
            "SELECT COUNT(*) as count FROM report WHERE reporter_id = ? AND target_id = ? AND created_at > datetime('now', '-1 day')",
            (session['user_id'], target_id)
        )
        report_count = cursor.fetchone()['count']
        
        if report_count >= 3:
            flash('동일 대상에 대한 신고 횟수가 제한을 초과했습니다. 24시간 후에 다시 시도해주세요.')
            return redirect(url_for('dashboard'))
        
        # 신고 접수
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, target_type, reason) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, target_type, reason)
        )
        
        # 신고 횟수 증가 및 상태 업데이트
        if target_type == 'user':
            cursor.execute("UPDATE user SET report_count = report_count + 1 WHERE id = ?", (target_id,))
            
            # 신고 횟수에 따른 사용자 상태 업데이트
            cursor.execute("SELECT report_count FROM user WHERE id = ?", (target_id,))
            user_report_count = cursor.fetchone()['report_count']
            
            if user_report_count >= 10:
                cursor.execute("UPDATE user SET status = 'dormant' WHERE id = ?", (target_id,))
            elif user_report_count >= 5:
                cursor.execute("UPDATE user SET status = 'warning' WHERE id = ?", (target_id,))
        
        else:  # product
            cursor.execute("UPDATE product SET report_count = report_count + 1 WHERE id = ?", (target_id,))
            
            # 신고 횟수에 따른 상품 상태 업데이트
            cursor.execute("SELECT report_count FROM product WHERE id = ?", (target_id,))
            product_report_count = cursor.fetchone()['report_count']
            
            if product_report_count >= 5:
                cursor.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (target_id,))
            elif product_report_count >= 3:
                cursor.execute("UPDATE product SET status = 'warning' WHERE id = ?", (target_id,))
        
        db.commit()
        
        # 감사 로그 기록
        log_action(session['user_id'], "REPORT", f"Reported {target_type}: {target_id}")
        
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    
    # GET 요청 처리
    target_id = request.args.get('target_id', '')
    target_type = request.args.get('target_type', 'product')
    
    return render_template('report.html', target_id=target_id, target_type=target_type)

# 1대1 채팅 목록
@app.route('/messages')
@login_required
def message_list():
    db = get_db()
    cursor = db.cursor()
    
    # 참여 중인 채팅방 목록 조회
    cursor.execute("""
        SELECT cr.id, cr.name, cp.user_id as participant_id, u.username as participant_name,
               (SELECT COUNT(*) FROM private_message WHERE receiver_id = ? AND sender_id = participant_id AND is_read = 0) as unread_count,
               (SELECT message FROM private_message WHERE (sender_id = ? AND receiver_id = participant_id) OR (sender_id = participant_id AND receiver_id = ?) ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM private_message WHERE (sender_id = ? AND receiver_id = participant_id) OR (sender_id = participant_id AND receiver_id = ?) ORDER BY created_at DESC LIMIT 1) as last_message_time
        FROM chat_room cr
        JOIN chat_participant cp ON cr.id = cp.room_id
        JOIN user u ON cp.user_id = u.id
        WHERE cr.id IN (SELECT room_id FROM chat_participant WHERE user_id = ?)
        AND cp.user_id != ?
    """, (session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id']))
    
    chat_rooms = cursor.fetchall()
    
    return render_template('message_list.html', chat_rooms=chat_rooms)

# 1대1 채팅방
@app.route('/messages/<user_id>', methods=['GET', 'POST'])
@login_required
def chat_room(user_id):
    if user_id == session['user_id']:
        flash('자기 자신과 채팅할 수 없습니다.')
        return redirect(url_for('message_list'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 상대방 사용자 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    other_user = cursor.fetchone()
    
    if not other_user:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('message_list'))
    
    # 채팅방 확인 또는 생성
    cursor.execute("""
        SELECT cr.id FROM chat_room cr
        JOIN chat_participant cp1 ON cr.id = cp1.room_id
        JOIN chat_participant cp2 ON cr.id = cp2.room_id
        WHERE cp1.user_id = ? AND cp2.user_id = ?
        LIMIT 1
    """, (session['user_id'], user_id))
    
    room = cursor.fetchone()
    
    if room:
        room_id = room['id']
    else:
        # 새 채팅방 생성
        room_id = str(uuid.uuid4())
        room_name = f"Chat between {session['user_id']} and {user_id}"
        
        cursor.execute("INSERT INTO chat_room (id, name) VALUES (?, ?)", (room_id, room_name))
        
        # 참가자 추가
        participant1_id = str(uuid.uuid4())
        participant2_id = str(uuid.uuid4())
        
        cursor.execute("INSERT INTO chat_participant (id, room_id, user_id) VALUES (?, ?, ?)", 
                      (participant1_id, room_id, session['user_id']))
        cursor.execute("INSERT INTO chat_participant (id, room_id, user_id) VALUES (?, ?, ?)", 
                      (participant2_id, room_id, user_id))
        
        db.commit()
    
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('chat_room', user_id=user_id))
        
        message = sanitize_input(request.form['message'])
        
        if not message or len(message) > 500:
            flash('메시지는 1-500자 사이여야 합니다.')
            return redirect(url_for('chat_room', user_id=user_id))
        
        # 메시지 저장
        message_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO private_message (id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)",
            (message_id, session['user_id'], user_id, message)
        )
        db.commit()
        
        # 실시간 알림 (Socket.IO)
        socketio.emit('new_message', {
            'room_id': room_id,
            'sender_id': session['user_id'],
            'message': message
        }, room=user_id)
        
        return redirect(url_for('chat_room', user_id=user_id))
    
    # 메시지 목록 조회
    cursor.execute("""
        SELECT pm.*, u.username as sender_name
        FROM private_message pm
        JOIN user u ON pm.sender_id = u.id
        WHERE (pm.sender_id = ? AND pm.receiver_id = ?) OR (pm.sender_id = ? AND pm.receiver_id = ?)
        ORDER BY pm.created_at ASC
    """, (session['user_id'], user_id, user_id, session['user_id']))
    
    messages = cursor.fetchall()
    
    # 읽지 않은 메시지 읽음 처리
    cursor.execute(
        "UPDATE private_message SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0",
        (user_id, session['user_id'])
    )
    db.commit()
    
    return render_template('chat_room.html', other_user=other_user, messages=messages, room_id=room_id)

# 관리자 페이지: 신고 관리
@app.route('/admin/reports')
@admin_required
def admin_reports():
    db = get_db()
    cursor = db.cursor()
    
    # 신고 목록 조회
    cursor.execute("""
        SELECT r.*, u1.username as reporter_name,
               CASE
                   WHEN r.target_type = 'user' THEN u2.username
                   WHEN r.target_type = 'product' THEN p.title
               END as target_name
        FROM report r
        JOIN user u1 ON r.reporter_id = u1.id
        LEFT JOIN user u2 ON r.target_type = 'user' AND r.target_id = u2.id
        LEFT JOIN product p ON r.target_type = 'product' AND r.target_id = p.id
        ORDER BY r.created_at DESC
    """)
    
    reports = cursor.fetchall()
    
    return render_template('admin_reports.html', reports=reports)

# 관리자 페이지: 신고 처리
@app.route('/admin/reports/<report_id>/process', methods=['POST'])
@admin_required
def process_report(report_id):
    # CSRF 토큰 검증
    if not validate_csrf_token():
        flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
        return redirect(url_for('admin_reports'))
    
    action = request.form.get('action')
    
    if action not in ['approve', 'reject']:
        flash('유효하지 않은 작업입니다.')
        return redirect(url_for('admin_reports'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 신고 정보 조회
    cursor.execute("SELECT * FROM report WHERE id = ?", (report_id,))
    report = cursor.fetchone()
    
    if not report:
        flash('존재하지 않는 신고입니다.')
        return redirect(url_for('admin_reports'))
    
    if action == 'approve':
        # 신고 승인 처리
        if report['target_type'] == 'user':
            # 사용자 휴면 처리
            cursor.execute("UPDATE user SET status = 'dormant' WHERE id = ?", (report['target_id'],))
        else:  # product
            # 상품 차단 처리
            cursor.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (report['target_id'],))
        
        cursor.execute("UPDATE report SET status = 'approved' WHERE id = ?", (report_id,))
        
        # 감사 로그 기록
        log_action(session['user_id'], "REPORT_APPROVE", f"Approved report: {report_id}")
        
        flash('신고가 승인되었습니다.')
    else:  # reject
        # 신고 거부 처리
        cursor.execute("UPDATE report SET status = 'rejected' WHERE id = ?", (report_id,))
        
        # 감사 로그 기록
        log_action(session['user_id'], "REPORT_REJECT", f"Rejected report: {report_id}")
        
        flash('신고가 거부되었습니다.')
    
    db.commit()
    
    return redirect(url_for('admin_reports'))

# 관리자 페이지: 불량 사용자 관리
@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 목록 조회
    cursor.execute("""
        SELECT u.*, 
               (SELECT COUNT(*) FROM report WHERE target_id = u.id AND target_type = 'user') as report_count
        FROM user u
        ORDER BY u.status DESC, u.report_count DESC, u.created_at DESC
    """)
    
    users = cursor.fetchall()
    
    return render_template('admin_users.html', users=users)

# 관리자 페이지: 사용자 상태 변경
@app.route('/admin/users/<user_id>/status', methods=['POST'])
@admin_required
def change_user_status(user_id):
    # CSRF 토큰 검증
    if not validate_csrf_token():
        flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
        return redirect(url_for('admin_users'))
    
    new_status = request.form.get('status')
    
    if new_status not in ['active', 'warning', 'dormant']:
        flash('유효하지 않은 상태입니다.')
        return redirect(url_for('admin_users'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('admin_users'))
    
    # 상태 변경
    cursor.execute("UPDATE user SET status = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    
    # 감사 로그 기록
    log_action(session['user_id'], "USER_STATUS_CHANGE", f"Changed user {user_id} status to {new_status}")
    
    flash('사용자 상태가 변경되었습니다.')
    return redirect(url_for('admin_users'))

# 관리자 페이지: 불량 상품 관리
@app.route('/admin/products')
@admin_required
def admin_products():
    db = get_db()
    cursor = db.cursor()
    
    # 상품 목록 조회
    cursor.execute("""
        SELECT p.*, u.username as seller_name,
               (SELECT COUNT(*) FROM report WHERE target_id = p.id AND target_type = 'product') as report_count
        FROM product p
        JOIN user u ON p.seller_id = u.id
        ORDER BY p.status DESC, p.report_count DESC, p.created_at DESC
    """)
    
    products = cursor.fetchall()
    
    return render_template('admin_products.html', products=products)

# 관리자 페이지: 상품 상태 변경
@app.route('/admin/products/<product_id>/status', methods=['POST'])
@admin_required
def change_product_status(product_id):
    # CSRF 토큰 검증
    if not validate_csrf_token():
        flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
        return redirect(url_for('admin_products'))
    
    new_status = request.form.get('status')
    
    if new_status not in ['active', 'warning', 'blocked']:
        flash('유효하지 않은 상태입니다.')
        return redirect(url_for('admin_products'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('admin_products'))
    
    # 상태 변경
    cursor.execute("UPDATE product SET status = ? WHERE id = ?", (new_status, product_id))
    db.commit()
    
    # 감사 로그 기록
    log_action(session['user_id'], "PRODUCT_STATUS_CHANGE", f"Changed product {product_id} status to {new_status}")
    
    flash('상품 상태가 변경되었습니다.')
    return redirect(url_for('admin_products'))

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    # 인증 확인
    if 'user_id' not in session:
        return
    
    # 메시지 속도 제한
    user_id = session['user_id']
    current_time = datetime.now()
    
    if user_id in message_rate_limit:
        last_message_time, count = message_rate_limit[user_id]
        time_diff = (current_time - last_message_time).total_seconds()
        
        # 10초 내에 5개 이상 메시지 전송 시 제한
        if time_diff < 10 and count >= 5:
            return
        
        # 10초가 지났으면 카운트 초기화
        if time_diff >= 10:
            message_rate_limit[user_id] = (current_time, 1)
        else:
            message_rate_limit[user_id] = (last_message_time, count + 1)
    else:
        message_rate_limit[user_id] = (current_time, 1)
    
    # 메시지 내용 검증 및 필터링
    if 'message' not in data or not data['message'] or len(data['message']) > 500:
        return
    
    # XSS 방어
    data['username'] = sanitize_input(data.get('username', '익명'))
    data['message'] = sanitize_input(data['message'])
    data['message_id'] = str(uuid.uuid4())
    
    # 감사 로그 기록
    log_action(user_id, "CHAT_MESSAGE", f"Chat message sent: {data['message'][:50]}...")
    
    send(data, broadcast=True)

# Socket.IO: 채팅방 참가
@socketio.on('join')
def on_join(data):
    if 'user_id' not in session:
        return
    
    room = data.get('room')
    if room:
        join_room(room)

# Socket.IO: 채팅방 퇴장
@socketio.on('leave')
def on_leave(data):
    if 'user_id' not in session:
        return
    
    room = data.get('room')
    if room:
        leave_room(room)

# Socket.IO: 1대1 메시지 전송
@socketio.on('private_message')
def handle_private_message(data):
    if 'user_id' not in session:
        return
    
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
    if not receiver_id or not message or len(message) > 500:
        return
    
    # XSS 방어
    message = sanitize_input(message)
    
    # 메시지 저장
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        message_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO private_message (id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)",
            (message_id, session['user_id'], receiver_id, message)
        )
        db.commit()
    
    # 메시지 전송
    emit('new_private_message', {
        'sender_id': session['user_id'],
        'message': message,
        'created_at': datetime.now().isoformat()
    }, room=receiver_id)


    # 사용자 프로필 조회
@app.route('/user/<user_id>')
def view_user(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 조회
    cursor.execute("SELECT id, username, bio, status, created_at FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 휴면 계정인 경우 접근 제한
    if user['status'] == 'dormant':
        flash('이 사용자는 현재 접근할 수 없습니다.')
        return redirect(url_for('dashboard'))
    
    # 사용자의 상품 조회
    cursor.execute("""
        SELECT * FROM product 
        WHERE seller_id = ? AND status != 'blocked'
        ORDER BY created_at DESC
    """, (user_id,))
    
    products = cursor.fetchall()
    
    # 현재 로그인한 사용자인지 확인
    is_owner = 'user_id' in session and session['user_id'] == user_id
    
    return render_template('view_user.html', user=user, products=products, is_owner=is_owner)

# 내 상품 관리 페이지
@app.route('/my_products')
@login_required
def my_products():
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자가 등록한 상품 조회
    cursor.execute("""
        SELECT * FROM product 
        WHERE seller_id = ? 
        ORDER BY created_at DESC
    """, (session['user_id'],))
    
    products = cursor.fetchall()
    
    return render_template('my_products.html', products=products)

# 상품 수정 페이지
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    
    # 상품 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('my_products'))
    
    # 본인 상품인지 확인
    if product['seller_id'] != session['user_id']:
        flash('자신의 상품만 수정할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # CSRF 토큰 검증
        if not validate_csrf_token():
            flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        title = sanitize_input(request.form['title'])
        description = sanitize_input(request.form['description'])
        price = sanitize_input(request.form['price'])
        
        # 입력값 검증
        if not title or len(title) < 2 or len(title) > 100:
            flash('제목은 2-100자 사이여야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        if not description or len(description) < 10 or len(description) > 1000:
            flash('설명은 10-1000자 사이여야 합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        if not validate_price(price):
            flash('가격은 숫자만 입력 가능합니다.')
            return redirect(url_for('edit_product', product_id=product_id))
        
        # 상품 정보 업데이트
        cursor.execute(
            "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
            (title, description, price, product_id)
        )
        db.commit()
        
        # 감사 로그 기록
        log_action(session['user_id'], "PRODUCT_UPDATE", f"Updated product: {title}")
        
        flash('상품 정보가 업데이트되었습니다.')
        return redirect(url_for('my_products'))
    
    return render_template('edit_product.html', product=product)

# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    # CSRF 토큰 검증
    if not validate_csrf_token():
        flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
        return redirect(url_for('my_products'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 상품 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('my_products'))
    
    # 본인 상품인지 확인
    if product['seller_id'] != session['user_id']:
        flash('자신의 상품만 삭제할 수 있습니다.')
        return redirect(url_for('dashboard'))
    
    # 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    # 감사 로그 기록
    log_action(session['user_id'], "PRODUCT_DELETE", f"Deleted product: {product['title']}")
    
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))

# 관리자: 상품 완전 삭제
@app.route('/admin/products/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    # CSRF 토큰 검증
    if not validate_csrf_token():
        flash('보안 토큰이 유효하지 않습니다. 다시 시도해주세요.')
        return redirect(url_for('admin_products'))
    
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('admin_products'))
    
    # 데이터베이스에서 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    
    # 관련된 신고 내역도 삭제
    cursor.execute("DELETE FROM report WHERE target_id = ? AND target_type = 'product'", (product_id,))
    
    db.commit()
    
    # 감사 로그 기록
    log_action(session['user_id'], "ADMIN_PRODUCT_DELETE", f"Admin deleted product: {product_id}")
    
    flash('상품이 데이터베이스에서 완전히 삭제되었습니다.')
    return redirect(url_for('admin_products'))

# 금지어 목록 (실제로는 더 많은 단어가 필요)
BANNED_WORDS = [
    '욕설', '비속어', '스팸', '광고', '사기', '불법', '도박', '성인',
    # 실제 욕설 등을 여기에 추가
]

# 텍스트에서 금지어 확인
def check_banned_content(text):
    if text is None:
        return False, []
    
    found_words = []
    for word in BANNED_WORDS:
        if word in text.lower():
            found_words.append(word)
    
    return len(found_words) > 0, found_words

# 기존 sanitize_input 함수 수정
def sanitize_input(text, check_banned=True):
    if text is None:
        return None
    
    # HTML 태그 제거 및 이스케이프 처리
    cleaned_text = bleach.clean(text, tags=[], strip=True)
    
    # 금지어 체크
    if check_banned:
        is_banned, banned_words = check_banned_content(cleaned_text)
        if is_banned:
            raise ValueError(f"금지어가 포함되어 있습니다: {', '.join(banned_words)}")
    
    return cleaned_text

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True, host='0.0.0.0')