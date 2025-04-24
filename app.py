import sqlite3
import uuid
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash  # 비밀번호 해싱
from functools import wraps  # 관리자 권한 확인을 위한 데코레이터


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
DATABASE = 'market.db'
socketio = SocketIO(app)


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
    	try:
    		pass
    	finally:
        	db.close()


# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # 사용자 테이블 생성 (관리자 권한 추가)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0  -- 0: 일반 사용자, 1: 관리자
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- 생성 시간
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP   -- 수정 시간
            )
        """)

        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                report_type TEXT NOT NULL,  -- 'user' or 'product'
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 관리자 계정 생성 (최초 실행 시에만)
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if cursor.fetchone() is None:  # 관리자 계정이 없으면 생성
            admin_id = str(uuid.uuid4())
            hashed_password = generate_password_hash('admin_password')  # 실제 비밀번호는 안전하게 설정
            cursor.execute("INSERT INTO user (id, username, password, is_admin) VALUES (?, ?, ?, ?)",
                           (admin_id, 'admin', hashed_password, 1))
                           
        db.commit()


# 관리자 권한 확인 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not is_admin(session['user_id']):
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# 관리자 여부 확인 함수
def is_admin(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return user and user['is_admin'] == 1


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
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()

        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)  # 비밀번호 해싱
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):  # 비밀번호 해싱 검증
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')


# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)


# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)


# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
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
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)


# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['seller_id'] != session['user_id']:
        flash('상품을 수정할 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        cursor.execute(
            "UPDATE product SET title = ?, description = ?, price = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (title, description, price, product_id)
        )
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product)


# 상품 삭제
@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    if product['seller_id'] != session['user_id']:
        flash('상품을 삭제할 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))


# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        report_type = request.form['report_type']  # 'user' or 'product' 인지 확인
        db = get_db()
        cursor = db.cursor()

        if report_type == 'user':
            cursor.execute("SELECT id FROM user WHERE id = ?", (target_id,))
            target = cursor.fetchone()
            if not target:
                flash('존재하지 않는 사용자 ID입니다.')
                return render_template('report.html')
        elif report_type == 'product':
            cursor.execute("SELECT id FROM product WHERE id = ?", (target_id,))
            target = cursor.fetchone()
            if not target:
                flash('존재하지 않는 상품 ID입니다.')
                return render_template('report.html')
        else:
            flash('잘못된 신고 유형입니다.')
            return render_template('report.html')

        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason, report_type) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason, report_type)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')


# 상품 검색
@app.route('/search')
def search_product():
    keyword = request.args.get('keyword', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE title LIKE ? OR description LIKE ?",
                   ('%' + keyword + '%', '%' + keyword + '%'))
    products = cursor.fetchall()
    return render_template('search_results.html', products=products, keyword=keyword)


# 사용자 삭제 (관리자 권한 필요)
@app.route('/admin/user/<user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM user WHERE id = ?", (user_id,))
    db.commit()
    flash('사용자가 삭제되었습니다.')
    return redirect(url_for('admin'))

# 상품 삭제 (관리자 권한 필요)
@app.route('/admin/product/<product_id>/delete', methods=['POST'])
@admin_required
def admin_delete_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin'))

# 관리자 페이지
@app.route('/admin')
@admin_required  # 관리자 권한 데코레이터 적용
def admin():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, is_admin FROM user")  # 필요한 정보만 선택
        users = [dict(row) for row in cursor.fetchall()]  # 딕셔너리 형태로 변환
        cursor.execute("SELECT id, title, price, seller_id FROM product")  # 필요한 정보만 선택
        products = [dict(row) for row in cursor.fetchall()]  # 딕셔너리 형태로 변환
        cursor.execute("SELECT id, reporter_id, target_id, reason, report_type FROM report")  # 필요한 정보만 선택
        reports = [dict(row) for row in cursor.fetchall()]  # 딕셔너리 형태로 변환
        return render_template('admin.html', users=users, products=products, reports=reports)
    except Exception as e:
        app.logger.error(f"Error in admin: {e}")
        flash('관리자 페이지 접근 중 오류가 발생했습니다.')
        return redirect(url_for('index'))


# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=False)
