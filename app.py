from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify,make_response
import pymysql
from flask_apscheduler import APScheduler
from datetime import timedelta, datetime
import logging
from config import Config

db_config = Config.DB_CONFIG

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.permanent_session_lifetime = timedelta(minutes=5)

logging.basicConfig(level=logging.DEBUG)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

@scheduler.task('interval', id='check_escalations', seconds=3600, misfire_grace_time=900)
def check_escalations():
    with app.app_context():
        check_and_escalate_claims()

def check_db_connection():
    try:
        conn = pymysql.connect(**db_config)
        conn.close()
        return True
    except pymysql.MySQLError as e:
        print(f"Error connecting to MySQL: {e}")
        return False

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if not check_db_connection():
        flash('Unable to connect to the database. Please try again later.')
        return redirect(url_for('home'))

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE username = %s", (username,))
    user = cur.fetchone()

    if user and password == user[2]:
        session.permanent = True
        session['username'] = user[1]
        session['role'] = user[4]
        session['user_id'] = user[0]
        conn.close()
        return redirect(url_for('login_success'))
    else:
        flash('Invalid username or password!')

    conn.close()
    return redirect(url_for('home'))

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['new_username']
    password = request.form['new_password']
    email = request.form['email']
    role = 'student'

    if not check_db_connection():
        flash('Unable to connect to the database. Please try again later.')
        return redirect(url_for('home'))

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    cur.execute("SELECT * FROM Users WHERE username = %s OR email = %s", (username, email))
    existing_user = cur.fetchone()

    if existing_user:
        flash('Username or email already exists!')
    else:
        cur.execute("INSERT INTO Users (username, password, email, role) VALUES (%s, %s, %s, %s)", 
                    (username, password, email, role))
        conn.commit()
        flash('Sign up successful! You can now log in.')
    conn.close()
    return redirect(url_for('home'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/login_success')
def login_success():
    if 'username' not in session:
        return redirect(url_for('home'))
    role = session.get('role')
    return redirect(url_for(f'{role}_info'))

@app.route('/escalate_violation', methods=['POST'])
def escalate_violation():
    if 'username' not in session or session.get('role') != 'committee':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.json
    report_id = data.get('report_id')

    if not report_id:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO Escalation (report_id, escalation_date)
            VALUES (%s, NOW())
            ON DUPLICATE KEY UPDATE escalation_date = NOW()
        """, (report_id,))

        insert_audit_log('escalation', report_id, session['user_id'], 'Violation escalated')

        conn.commit()
        return jsonify({'success': True, 'message': 'Violation escalated successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/student_info')
def student_info():
    if 'username' not in session or session.get('role') != 'student':
        flash('Please log in to access this page.')
        return redirect(url_for('home'))

    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("""
            SELECT vr.*, u.username as professor_name, 
                   c.comment_text, c.comment_date
            FROM ViolationReport vr
            JOIN Users u ON vr.professor_id = u.id
            LEFT JOIN (
                SELECT report_id, comment_text, comment_date,
                       ROW_NUMBER() OVER (PARTITION BY report_id ORDER BY comment_date DESC) as rn
                FROM Comment
            ) c ON vr.report_id = c.report_id AND c.rn = 1
            WHERE vr.student_id = %s AND vr.is_hidden = 0
            ORDER BY vr.date_reported DESC
        """, (session['user_id'],))
        violations = cur.fetchall()
        
        cur.execute("""
            SELECT * FROM Notification 
            WHERE user_id = %s AND is_read = 0 
            ORDER BY date_sent DESC
        """, (session['user_id'],))
        notifications = cur.fetchall()
        
        return render_template("student_info.html", violations=violations, notifications=notifications)
    finally:
        cur.close()
        conn.close()



@app.route('/teacher_info')
def teacher_info():
    if 'username' not in session or session.get('role') != 'teacher':
        flash('Please log in to access this page.')
        return redirect(url_for('home'))

    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("""
            SELECT vr.*, u.username as student_name, 
                   c.comment_text, c.comment_date
            FROM ViolationReport vr
            JOIN Users u ON vr.student_id = u.id
            LEFT JOIN (
                SELECT report_id, comment_text, comment_date,
                       ROW_NUMBER() OVER (PARTITION BY report_id ORDER BY comment_date DESC) as rn
                FROM Comment
            ) c ON vr.report_id = c.report_id AND c.rn = 1
            WHERE vr.professor_id = %s AND vr.is_hidden = 0
            ORDER BY vr.date_reported DESC
        """, (session['user_id'],))
        violations = cur.fetchall()
        
        cur.execute("""
            SELECT * FROM Notification 
            WHERE user_id = %s AND is_read = 0 
            ORDER BY date_sent DESC
        """, (session['user_id'],))
        notifications = cur.fetchall()
        
        return render_template("teacher_info.html", violations=violations, notifications=notifications)
    finally:
        cur.close()
        conn.close()


def insert_audit_log(action_type, report_id, user_id, action_description):
    conn = pymysql.connect(**db_config)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO AuditLog (action_type, report_id, user_id, action_description, action_date)
            VALUES (%s, %s, %s, %s, NOW())
        """, (action_type, report_id, user_id, action_description))
        conn.commit()
    except Exception as e:
        print(f"Error inserting audit log: {str(e)}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()



@app.route('/respond/<int:report_id>', methods=['GET', 'POST'])
def respond(report_id):
    if 'username' not in session:
        flash('Please log in to access this page.')
        return redirect(url_for('home'))
    
    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    
    cur.execute("SELECT * FROM ViolationReport WHERE report_id = %s", (report_id,))
    violation = cur.fetchone()
    
    if not violation:
        flash('Violation report not found.')
        return redirect(url_for(f"{session['role']}_info"))
    
    if request.method == 'POST':
        response_text = request.form.get('response')
        if response_text:
            cur.execute("""
                INSERT INTO Comment (report_id, user_id, comment_text, comment_date)
                VALUES (%s, %s, %s, %s)
            """, (report_id, session['user_id'], response_text, datetime.now()))
            conn.commit()
            flash('Response submitted successfully.')
            return redirect(url_for(f"{session['role']}_info"))
        else:
            flash('Response cannot be empty.')

    conn.close()
    return render_template("response_form.html", violation=violation)

@app.route('/file_violation_form')
def file_violation_form():
    if 'username' not in session or session.get('role') != 'teacher':
        flash('Please log in as a teacher to access this page.')
        return redirect(url_for('home'))
    return render_template('file_violation_form.html')

@app.route('/committee_info')
def committee_info():
    if 'username' not in session or session.get('role') != 'committee':
        flash('Please log in to access this page.')
        return redirect(url_for('home'))

    page = request.args.get('page', 1, type=int)
    per_page = 5
    violations = get_all_violations()
    total_pages = (len(violations) - 1) // per_page + 1
    start = (page - 1) * per_page
    end = start + per_page
    paginated_violations = violations[start:end]

    return render_template("committee_info.html",
                         violations=paginated_violations,
                         total_pages=total_pages,
                         current_page=page)




def get_all_violations():
    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("""
            SELECT vr.*,
                s.username as student_name,
                p.username as professor_name,
                CASE 
                    WHEN vr.status != 'Closed' 
                    AND TIMESTAMPDIFF(HOUR, vr.date_reported, NOW()) > 24 
                    THEN 1 
                    ELSE 0 
                END as is_escalated
            FROM ViolationReport vr
            JOIN Users s ON vr.student_id = s.id
            JOIN Users p ON vr.professor_id = p.id
            WHERE vr.is_hidden = 0 or vr.is_hidden= NULL
            ORDER BY vr.date_reported DESC
        """)
        violations = cur.fetchall()
        return violations
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return []
    finally:
        cur.close()
        conn.close()



@app.route('/hide_violation', methods=['POST'])
def hide_violation():
    if 'username' not in session or session.get('role') != 'committee':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.json
    violation_id = data.get('violation_id')

    if not violation_id:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    try:
        cur.execute("""
            UPDATE ViolationReport
            SET is_hidden = 1
            WHERE report_id = %s
        """, (violation_id,))

        insert_audit_log('hide_violation', violation_id, session['user_id'], 'Violation hidden after decision')

        conn.commit()
        return jsonify({'success': True, 'message': 'Violation hidden successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()




@app.route('/search_violation', methods=['POST'])
def search_violation():
    if 'username' not in session or session.get('role') != 'committee':
        return jsonify({'error': 'Unauthorized'}), 401

    case_number = request.json.get('case_number')
    
    violations = get_violations_by_case_number(case_number)
    
    return render_template('violations_list.html', violations=violations)

def get_all_violations():
    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("""
        SELECT vr.*,
            s.username as student_name,
            p.username as professor_name
        FROM ViolationReport vr
        JOIN Users s ON vr.student_id = s.id
        JOIN Users p ON vr.professor_id = p.id
        WHERE vr.is_hidden = 0
        ORDER BY vr.date_reported DESC
        """)
        violations = cur.fetchall()
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        violations = []
    finally:
        cur.close()
        conn.close()
    return violations


def get_violations_by_case_number(case_number):
    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    try:
        cur.execute("""
        SELECT vr.*,
            s.username as student_name,
            p.username as professor_name
        FROM ViolationReport vr
        JOIN Users s ON vr.student_id = s.id
        JOIN Users p ON vr.professor_id = p.id
        WHERE vr.report_id = %s AND vr.is_hidden = 0
        """, (case_number,))
        violations = cur.fetchall()
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        violations = []
    finally:
        cur.close()
        conn.close()
    return violations


def check_and_escalate_claims():
    conn = pymysql.connect(**db_config)
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT report_id
            FROM ViolationReport
            WHERE status != 'Closed'
            AND TIMESTAMPDIFF(HOUR, date_reported, NOW()) > 24
        """)
        unresolved_claims = cur.fetchall()
        
        for claim in unresolved_claims:
            cur.execute("""
                INSERT INTO Escalation (report_id, escalation_date)
                VALUES (%s, NOW())
                ON DUPLICATE KEY UPDATE escalation_date = NOW()
            """, (claim[0],))
        
        conn.commit()
    except Exception as e:
        print(f"Error in check_and_escalate_claims: {str(e)}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

@app.route('/documents/<int:v_report_id>')
def documents(v_report_id):
    if 'username' not in session:
         flash('Please log in to access this page.')
         return redirect(url_for('home'))

    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
         cur.execute("""
             SELECT doc.doc_id, doc.filename 
             FROM upload_docs doc 
             WHERE doc.report_id = %s
         """, (v_report_id,))
         documents = cur.fetchall()
         
         return render_template('documents.html', documents=documents, report_id=v_report_id)
    
    except Exception as e:
         print(f"An error occurred while fetching documents for violation {v_report_id}: {str(e)}")
         flash('Could not retrieve documents.')
         return redirect(url_for('committee_info'))
    
    finally:
         cur.close()
         conn.close()

@app.route('/download_doc/<int:file_id>')
def download_doc(file_id):
    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    try:
         cur.execute("""
             SELECT filename, file_data 
             FROM upload_docs 
             WHERE doc_id = %s
         """, (file_id,))
         file_record = cur.fetchone()

         if file_record:
             filename = file_record[0]
             file_data = file_record[1]

             response = make_response(file_data)
             response.headers['Content-Disposition'] = f'attachment; filename={filename}'
             response.headers['Content-Type'] = 'application/octet-stream'
             return response

         else:
             flash('File not found.')
             return redirect(url_for('committee_info'))

    except Exception as e:
         print(f"An error occurred while downloading document {file_id}: {str(e)}")
         flash('Could not download the document.')
         return redirect(url_for('committee_info'))

    finally:
         cur.close()
         conn.close()


@app.route('/submit_docs', methods=['POST'])
def submit_docs():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    report_id = request.form.get('report_id')
    comment_text = request.form.get('comment_text')

    if not report_id or not comment_text:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    user_id = session.get('user_id') 

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    try:
        
        cur.execute("""
            INSERT INTO Comment (report_id, user_id, comment_text, comment_date)
            VALUES (%s, %s, %s, NOW())
        """, (report_id, user_id, comment_text))

        if 'document' in request.files:
            document = request.files['document']
            
            if document:
                filename = document.filename
                file_data = document.read() 
                
                cur.execute("""
                    INSERT INTO upload_docs (report_id, user_id, filename, file_data)
                    VALUES (%s, %s, %s, %s)
                """, (report_id, user_id, filename, file_data))

        conn.commit()
        
        return jsonify({'success': True})
    
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    
    finally:
        cur.close()
        conn.close()
@app.route('/decision_input/<int:violation_id>')
def decision_input(violation_id):
    if 'username' not in session or session.get('role') != 'committee':
        flash('Please log in to access this page.')
        return redirect(url_for('home'))
    
    violation = get_violation_by_id(violation_id)
    
    if not violation:
        flash('Violation not found.')
        return redirect(url_for('committee_info'))
    
    return render_template('decision_input_page.html', violation=violation)

def insert_audit_log(action_type, report_id, user_id, action_description):
    conn = pymysql.connect(**db_config)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO AuditLog (action_type, report_id, user_id, action_description, action_date)
            VALUES (%s, %s, %s, %s, NOW())
        """, (action_type, report_id, user_id, action_description))
        conn.commit()
    except Exception as e:
        print(f"Error inserting audit log: {str(e)}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

@app.route('/status_history/<int:violation_id>')
def status_history(violation_id):
    if 'username' not in session or session.get('role') != 'committee':
        flash('Please log in to access this page.')
        return redirect(url_for('home'))
    
    comments = get_comments_by_violation_id(violation_id)
    
    insert_audit_log('view', violation_id, session['user_id'], 'Committee member viewed status history')
    
    return render_template('status_history.html', violation_id=violation_id, comments=comments)

@app.route('/submit_decision', methods=['POST'])
def submit_decision():
    if 'username' not in session or session.get('role') != 'committee':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.json
    violation_id = data.get('violation_id')
    decision = data.get('decision')

    if not violation_id or not decision:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    try:
        cur.execute("""
        UPDATE ViolationReport SET status = 'Closed', is_hidden = 1 WHERE report_id = %s
        """, (violation_id,))

        cur.execute("""
        INSERT INTO StatusHistory (report_id, status, changed_by, change_date)
        VALUES (%s, %s, %s, NOW())
        """, (violation_id, decision, session['user_id']))  

        cur.execute("SELECT student_id FROM ViolationReport WHERE report_id = %s", (violation_id,))
        student_id = cur.fetchone()[0]

        notification_message = f"Your appeal for Violation #{violation_id} has been processed with decision: {decision}."
        cur.execute("""
        INSERT INTO Notification (user_id, report_id, message, is_read, date_sent)
        VALUES (%s, %s, %s, %s, NOW())
        """, (student_id, violation_id, notification_message, 0))

        insert_audit_log('decision', violation_id, session['user_id'], f'Decision submitted: {decision}')

        conn.commit()
        return jsonify({'success': True, 'message': 'Decision submitted successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()
        
def get_violation_by_id(violation_id):
    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    
    try:
        cur.execute("""
            SELECT vr.*, 
                   s.username as student_name, 
                   p.username as professor_name
            FROM ViolationReport vr
            JOIN Users s ON vr.student_id = s.id
            JOIN Users p ON vr.professor_id = p.id
            WHERE vr.report_id = %s
        """, (violation_id,))
        violation = cur.fetchone()
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        violation = None
    finally:
        cur.close()
        conn.close()
    
    return violation


@app.route('/update_status', methods=['POST'])
def update_status():
    if 'username' not in session or session.get('role') != 'committee':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.json
    violation_id = data.get('violation_id')
    new_status = data.get('new_status')

    if not violation_id or not new_status:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    try:
        cur.execute("""
            UPDATE ViolationReport
            SET status = %s
            WHERE report_id = %s
        """, (new_status, violation_id)) 
        cur.execute("""
            UPDATE ViolationReport SET status = %s WHERE report_id = %s
        """, (new_status, violation_id))
    
        insert_audit_log('status change', violation_id, session['user_id'], f'Status changed to {new_status}')
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Status updated successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/submit_response', methods=['POST'])
def submit_response():
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    report_id = request.form.get('report_id')
    comment_text = request.form.get('comment_text')
    response_type = request.form.get('response_type')
    user_id = session.get('user_id')

    if not report_id or not comment_text or not response_type:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400

    conn = pymysql.connect(**db_config)
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO Comment (report_id, user_id, comment_text, comment_date)
            VALUES (%s, %s, %s, NOW())
        """, (report_id, user_id, comment_text))

        cur.execute("""
            INSERT INTO StatusHistory (report_id, status, changed_by, change_date)
            VALUES (%s, %s, %s, NOW())
        """, (report_id, response_type, user_id))


        cur.execute("SELECT professor_id FROM ViolationReport WHERE report_id = %s", (report_id,))
        professor_result = cur.fetchone()

        if professor_result:
            professor_id = professor_result[0]

            # Insert notification for the teacher
            notification_message = f"Student has responded to Violation #{report_id}."
            cur.execute("""
                INSERT INTO Notification (user_id, report_id, message, is_read, date_sent)
                VALUES (%s, %s, %s, %s, NOW())
            """, (professor_id, report_id, notification_message, 0))

        # Handle file upload if present
        if 'document' in request.files:
            document = request.files['document']
            
            if document:
                filename = document.filename
                file_data = document.read()
                
                cur.execute("""
                    INSERT INTO upload_docs (report_id, user_id, filename, file_data)
                    VALUES (%s, %s, %s, %s)
                """, (report_id, user_id, filename, file_data))

        conn.commit()
        
        insert_audit_log('comment', report_id, user_id, f'User added a comment and responded with {response_type}')
        
        return jsonify({'success': True, 'message': 'Response submitted successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close() 
        conn.close()


@app.route('/submit_violation', methods=['POST'])
def submit_violation():
    if 'username' not in session or session.get('role') != 'teacher':
        flash('Please log in as a teacher to file a violation.')
        return redirect(url_for('home'))

    student_name = request.form['studentName']
    violation_description = request.form['violationDescription']
    professor_id = session['user_id']
    
    logging.debug(f"Received violation report: Student: {student_name}, Description: {violation_description}, Professor ID: {professor_id}")

    conn = None
    try:
        conn = pymysql.connect(**db_config)
        cur = conn.cursor()

        cur.execute("SELECT id FROM Users WHERE username = %s AND role = 'student'", (student_name,))
        student_result = cur.fetchone()
        
        if not student_result:
            flash('Student not found.')
            logging.error(f"Student not found: {student_name}")
            return redirect(url_for('file_violation_form'))

        student_id = student_result[0]
        logging.debug(f"Found student ID: {student_id}")

        cur.execute("SELECT id FROM Users WHERE role = 'committee' ORDER BY RAND() LIMIT 1")
        committee_result = cur.fetchone()
        
        if not committee_result:
            flash('No committee member available.')
            logging.error("No committee member found")
            return redirect(url_for('file_violation_form'))

        committee_member_id = committee_result[0]
        logging.debug(f"Selected committee member ID: {committee_member_id}")

        insert_query = """
            INSERT INTO ViolationReport (professor_id, student_id, committee_member_id, violation_description, status, date_reported)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        insert_values = (professor_id, student_id, committee_member_id, violation_description, 'Pending', datetime.now())
        
        logging.debug(f"Executing insert query: {insert_query} with values: {insert_values}")
        
        cur.execute(insert_query, insert_values)
        
        report_id = cur.lastrowid

        notification_message = f"A violation report has been filed against you."
        cur.execute("""
            INSERT INTO Notification (user_id, report_id, message, is_read, date_sent)
            VALUES (%s, %s, %s, %s, NOW())
        """, (student_id, report_id, notification_message, 0))  

        conn.commit()
        
        flash('Violation report filed successfully.')
        logging.info("Violation report filed successfully")

        cur.execute(insert_query, insert_values)
        report_id = cur.lastrowid
        conn.commit()
        
        insert_audit_log('view', report_id, professor_id, 'Professor filed a new violation report')
        
        flash('Violation report filed successfully.')
        logging.info("Violation report filed successfully")

    except Exception as e:
        if conn:
            conn.rollback()
        flash(f'An error occurred: {str(e)}')
        logging.error(f"Error occurred: {str(e)}", exc_info=True)

    finally:
        if conn:
            conn.close()

    return redirect(url_for('teacher_info'))


def get_comments_by_violation_id(violation_id):
    conn = pymysql.connect(**db_config)
    cur = conn.cursor(pymysql.cursors.DictCursor)

    try:
        cur.execute("""
            SELECT c.comment_text, c.comment_date
            FROM Comment c
            WHERE c.report_id = %s
            ORDER BY c.comment_date DESC
        """, (violation_id,))
        comments = cur.fetchall()
    except Exception as e:
        print(f"An error occurred while fetching comments for violation {violation_id}: {str(e)}")
        comments = []
    finally:
        cur.close()
        conn.close()

    return comments

@app.route('/update_student_status', methods=['POST'])
def update_student_status():
    if 'username' not in session or session.get('role') != 'student':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.json
    report_id = data.get('report_id')
    status = data.get('status')
    
    if not report_id or not status:
        return jsonify({'success': False, 'message': 'Invalid data'}), 400
    
    conn = pymysql.connect(**db_config)
    cur = conn.cursor()
    
    try:
        cur.execute("""
            UPDATE ViolationReport SET status = %s WHERE report_id = %s
        """, (status, report_id))
        
        cur.execute("""
            INSERT INTO StatusHistory (report_id, status, changed_by, change_date)
            VALUES (%s, %s, %s, NOW())
        """, (report_id, status, session['user_id']))
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Status updated successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/check_session', methods=['POST'])
def check_session():
    if 'username' in session and session.get('role') in ['student', 'teacher', 'committee']:
        return jsonify({'valid': True})
    return jsonify({'valid': False})

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

@app.before_request
def ensure_no_cache():
    if 'username' not in session and request.endpoint not in ['home', 'login', 'signup', 'check_session']:
        flash('Please log in first.')
        return redirect(url_for('home'))
    return None

if __name__ == '__main__':
    app.run(debug=True)
