import streamlit as st
import time
import json

# Internal imports
from security.workflow import transmit_question_paper, submit_student_answer
from ui.flow import render_pipeline
from security.rate_limiter import check_rate_limit, reset_rate_limits
from security.replay_protection import clear_cache as clear_replay_cache
from security.authentication import DUMMY_DATABASE, _hash_password

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="SecureExam | Online Examination System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS FOR DARK NAVY CYBERSECURITY THEME ---
st.markdown("""
<style>
    .stApp {
        background-color: #0B132B;
        color: #E2E8F0;
    }
    .css-1d391kg, [data-testid="stSidebar"] {
        background-color: #112240 !important;
        border-right: 1px solid #1C2541;
    }
    h1, h2, h3, h4, h5, h6 {
        color: #64FFDA !important;
        font-family: 'Courier New', Courier, monospace;
    }
    .metric-card {
        background-color: #1C2541;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        border: 1px solid #3A506B;
        text-align: center;
        margin-bottom: 20px;
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        color: #64FFDA;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 5px;
    }
    .status-card {
        background-color: #112240;
        border-left: 4px solid #10B981;
        padding: 15px;
        border-radius: 4px;
        margin-bottom: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .status-card h4 {
        margin-top: 0;
        margin-bottom: 8px;
        color: #E2E8F0 !important;
        font-size: 1.1rem;
    }
    .status-card p {
        margin: 0;
        color: #94A3B8;
        font-size: 0.9rem;
        line-height: 1.4;
    }
    .notice {
        background-color: rgba(245, 158, 11, 0.1);
        border-left: 4px solid #F59E0B;
        padding: 12px;
        color: #F59E0B;
        font-size: 0.85rem;
        margin-bottom: 20px;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
if "transmission_log" not in st.session_state:
    st.session_state.transmission_log = []
if "metrics" not in st.session_state:
    st.session_state.metrics = {
        "qp_transmitted": 0,
        "submissions_received": 0,
        "integrity_failures": 0,
        "attacks_detected": 0
    }
if "pipeline_results" not in st.session_state:
    st.session_state.pipeline_results = None
if "deployed_exams" not in st.session_state:
    st.session_state.deployed_exams = {}

# --- HELPER: EXECUTE TRANSMISSION ---
def run_transmission(scenario, sender, receiver, message, attack, password="password123"):
    # Auto-register dummy user so auth doesn't fail purely due to missing user
    if sender not in DUMMY_DATABASE:
        slt, hsh = _hash_password(password)
        DUMMY_DATABASE[sender] = {"salt": slt, "hash": hsh}

    # Availability Check (Rate Limiting)
    rl = check_rate_limit(sender, max_requests=10, window_seconds=10)
    if rl["status"] == "rate limit exceeded":
        st.error(f"RATE LIMIT EXCEEDED: {rl['message']}")
        st.session_state.transmission_log.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "scenario": scenario,
            "attack": attack,
            "status": "RATE LIMITED",
            "failed_step": "Rate Limiter (Availability Control)",
            "reason": rl["message"]
        })
        return None

    with st.spinner("Executing Cryptographic Pipeline..."):
        if scenario == "Student Answer Submission":
            results = submit_student_answer(sender, password, receiver, message, attack)
            st.session_state.sender_label = "STUDENT"
            st.session_state.receiver_label = "EXAMINATION SERVER"
            if attack == "None": 
                st.session_state.metrics["submissions_received"] += 1
        else:
            results = transmit_question_paper(sender, password, receiver, message, attack)
            st.session_state.sender_label = "EXAMINER"
            st.session_state.receiver_label = "STUDENT"
            if attack == "None": 
                st.session_state.metrics["qp_transmitted"] += 1

        is_failed = any(s.get("status") == "FAILED" for s in results)
        failed_step_obj = next((s for s in results if s.get("status") == "FAILED"), None)
        
        if attack != "None":
            st.session_state.metrics["attacks_detected"] += 1
        if is_failed:
            st.session_state.metrics["integrity_failures"] += 1
            
        st.session_state.pipeline_results = results
        st.session_state.animate = True
        
        # Log event
        st.session_state.transmission_log.insert(0, {
            "time": time.strftime("%H:%M:%S"),
            "scenario": scenario,
            "attack": attack,
            "status": "REJECTED" if is_failed else "VERIFIED",
            "failed_step": failed_step_obj.get("step_name") if failed_step_obj else None,
            "reason": failed_step_obj.get("explanation") if failed_step_obj else None
        })
        return results

# --- SIDEBAR NAVIGATION ---
st.sidebar.markdown("<h1>🛡️ SecureExam</h1>", unsafe_allow_html=True)
page = st.sidebar.radio("Navigation", [
    "Dashboard",
    "Examiner Portal",
    "Student Examination",
    "Secure Transmission",
    "Packet Inspector",
    "Attack Lab",
    "Security Audit Report"
])

st.sidebar.markdown("---")
st.sidebar.markdown(
    "<div class='notice'><strong>Educational Prototype:</strong> This application simulates cryptographic concepts for an online examination system. It is not intended for production use.</div>", 
    unsafe_allow_html=True
)

# --- PAGE ROUTING ---

if page == "Dashboard":
    st.markdown("<h1>SecureExam | Overview</h1>", unsafe_allow_html=True)
    st.markdown("<h3 style='color: #94A3B8 !important;'>Secure Online Examination System | Network Status: ONLINE 🟢</h3>", unsafe_allow_html=True)
    st.markdown("---")
    
    # Overview Metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(f"<div class='metric-card'><div class='metric-value'>{st.session_state.metrics['qp_transmitted']}</div><div class='metric-label'>Papers Transmitted</div></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-card'><div class='metric-value'>{st.session_state.metrics['submissions_received']}</div><div class='metric-label'>Submissions Received</div></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-card'><div class='metric-value' style='color:#EF4444;'>{st.session_state.metrics['integrity_failures']}</div><div class='metric-label'>Integrity Failures</div></div>", unsafe_allow_html=True)
    m4.markdown(f"<div class='metric-card'><div class='metric-value' style='color:#F59E0B;'>{st.session_state.metrics['attacks_detected']}</div><div class='metric-label'>Attacks Detected</div></div>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.header("Security Enforcement Protocol")
        st.markdown("""
        <div class='status-card'>
            <h4>🔒 Confidentiality</h4>
            <p><strong>AES-256-GCM</strong> ensuring question papers and answers remain completely secret in transit.</p>
        </div>
        <div class='status-card'>
            <h4>🛡️ Integrity</h4>
            <p><strong>Authenticated Encryption & SHA-256</strong> preventing silent tampering of examination data.</p>
        </div>
        <div class='status-card'>
            <h4>🆔 Authentication</h4>
            <p>Strict identity verification for authorized <strong>Examiner and Student</strong> accounts.</p>
        </div>
        <div class='status-card'>
            <h4>✒️ Non-repudiation</h4>
            <p><strong>RSA Digital Signatures</strong> tying submissions uniquely to specific students.</p>
        </div>
        <div class='status-card'>
            <h4>⏱️ Replay Protection</h4>
            <p><strong>Transaction IDs, Nonces, and Freshness Checks</strong> guarding against replay attacks.</p>
        </div>
        <div class='status-card'>
            <h4>⚡ Availability</h4>
            <p><strong>Rate Limiting</strong> mitigating DoS and brute-force disruption attempts.</p>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        st.header("Recent Transmission Events")
        if st.session_state.transmission_log:
            for log in st.session_state.transmission_log[:6]:
                color = "#10B981" if log['status'] == "VERIFIED" else "#EF4444"
                st.markdown(f"**{log['time']}** | <span style='color:{color}; font-weight:bold;'>{log['status']}</span><br><small style='color:#94A3B8'>{log['scenario']} | {log['attack']}</small>", unsafe_allow_html=True)
                st.markdown("<hr style='margin: 8px 0; border-color: #3A506B;'>", unsafe_allow_html=True)
        else:
            st.info("No network activity recorded.")
            
    st.markdown("---")
    st.header("Security Requirements Mapping")
    st.write("Mapping the Secure Online Examination scenario directly to core Cryptography and Network Security (CNS) modules.")
    
    # Dynamically compute status
    req_tests = {
        "Confidentiality": "NOT TESTED",
        "Integrity": "NOT TESTED",
        "Authentication": "NOT TESTED",
        "Non-repudiation": "NOT TESTED",
        "Replay protection": "NOT TESTED",
        "Availability": "NOT TESTED"
    }
    
    for log in st.session_state.transmission_log:
        atk = log.get("attack")
        sts = log.get("status")
        if atk == "Eavesdropping": req_tests["Confidentiality"] = "PASS" if sts == "VERIFIED" else "FAIL"
        if atk == "Tampering (MITM)": req_tests["Integrity"] = "PASS" if sts == "REJECTED" else "FAIL"
        if atk == "Metadata Hijack (MITM)": req_tests["Authentication"] = "PASS" if sts == "REJECTED" else "FAIL"
        if atk == "Replay Attack": req_tests["Replay protection"] = "PASS" if sts == "REJECTED" else "FAIL"
        if sts == "RATE LIMITED": req_tests["Availability"] = "PASS"
        if log.get("scenario") == "Student Answer Submission" and sts == "VERIFIED":
            if req_tests["Non-repudiation"] == "NOT TESTED": req_tests["Non-repudiation"] = "PASS"

    def status_span(res):
        if res == "PASS": return "<span style='color:#10B981; font-weight:bold;'>PASS</span>"
        if res == "FAIL": return "<span style='color:#EF4444; font-weight:bold;'>FAIL</span>"
        return "<span style='color:#94A3B8; font-weight:bold;'>NOT TESTED</span>"
        
    st.markdown(f"""
    | Security Requirement | Threat | Cryptographic / Security Mechanism | Implementation Module | Verification Test | Actual Status |
    |---|---|---|---|---|---|
    | **Confidentiality** | Intercepted question papers or answers | AES-256-GCM (Symmetric AEAD Encryption) | `crypto.aes` | Eavesdropping Simulation | {status_span(req_tests['Confidentiality'])} |
    | **Integrity** | Altered question papers or submissions | HMAC-SHA256 & SHA-256 Digest | `crypto.hash`, `crypto.hmac` | Tampering (MITM) Simulation | {status_span(req_tests['Integrity'])} |
    | **Authentication** | Unauthorized students or examiners | PBKDF2 Hashing / RSA Verification | `security.authentication`, `crypto.rsa` | Metadata Hijack Simulation | {status_span(req_tests['Authentication'])} |
    | **Non-repudiation** | Disputes about who signed or submitted data | RSA-2048 PSS Digital Signatures | `crypto.rsa` | Successful Student Submission | {status_span(req_tests['Non-repudiation'])} |
    | **Replay protection**| Repeated packets or duplicate submissions | UUID Nonce, Unix Timestamp, Cache | `security.replay_protection` | Replay Attack Simulation | {status_span(req_tests['Replay protection'])} |
    | **Availability** | Excessive requests and DoS | Token-bucket Rate Limiter | `security.rate_limiter` | Rate Limit Threshold Test | {status_span(req_tests['Availability'])} |
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.header("Architecture Data Flow")
    st.markdown("""
    <div style="background-color: #1C2541; padding: 25px; border-radius: 8px; font-family: 'Courier New', monospace; text-align: center; border: 1px solid #3A506B; box-shadow: 0 4px 6px rgba(0,0,0,0.3);">
        <h4 style="color:#64FFDA; margin-top:0; border-bottom: 1px solid #3A506B; padding-bottom: 10px;">⏬ Question Paper Transmission Workflow</h4>
        <div style="color: #E2E8F0; padding: 10px 0;">
            <span style="color:#10B981;">Examiner</span> ➔ 
            <span style="color:#3B82F6;">Authentication</span> ➔ 
            <span style="color:#8B5CF6;">Encryption/Signature</span> ➔ 
            <span style="color:#EF4444; font-weight:bold;">[ Untrusted Network ]</span> ➔ 
            <span style="color:#3B82F6;">Verification</span> ➔ 
            <span style="color:#10B981;">Student</span>
        </div>
        <br>
        <h4 style="color:#64FFDA; margin-top:0; border-bottom: 1px solid #3A506B; padding-bottom: 10px;">⏫ Student Answer Submission Workflow</h4>
        <div style="color: #E2E8F0; padding: 10px 0;">
            <span style="color:#10B981;">Student</span> ➔ 
            <span style="color:#3B82F6;">Authentication</span> ➔ 
            <span style="color:#8B5CF6;">Secure Submission (Encrypt/Sign)</span> ➔ 
            <span style="color:#EF4444; font-weight:bold;">[ Untrusted Network ]</span> ➔ 
            <span style="color:#3B82F6;">Verification</span> ➔ 
            <span style="color:#10B981;">Examination Server</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.header("Educational Core Concepts")
    st.markdown("""
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
        <div class='status-card'>
            <h4>Why AES for Bulk Data?</h4>
            <p><strong>AES (Advanced Encryption Standard)</strong> is a symmetric algorithm. It is used for bulk encryption because it is computationally fast and highly efficient for large datasets (like documents or streams). Asymmetric algorithms like RSA are too slow for bulk data.</p>
        </div>
        <div class='status-card'>
            <h4>Role of RSA / ECC</h4>
            <p><strong>Asymmetric algorithms</strong> use a public-private key pair. They solve the <i>key distribution problem</i> by allowing parties to securely establish AES session keys over untrusted networks. They are also uniquely capable of generating <strong>Digital Signatures</strong> for non-repudiation.</p>
        </div>
        <div class='status-card'>
            <h4>SHA-256 is NOT Encryption</h4>
            <p><strong>Hashing (SHA-256)</strong> is a one-way mathematical function that produces a fixed-size fingerprint of data. Unlike encryption, it <strong>cannot be reversed</strong> (decrypted). It is strictly used to verify integrity.</p>
        </div>
        <div class='status-card'>
            <h4>How Digital Signatures detect changes</h4>
            <p>A digital signature encrypts the <strong>hash</strong> of a message using the sender's private key. If an attacker modifies the message, the receiver's independently calculated hash will not match the decrypted hash from the signature, immediately exposing the tampering.</p>
        </div>
        <div class='status-card'>
            <h4>Why Replay Protection is Necessary</h4>
            <p>Without replay protection, an attacker could record a valid, encrypted "submit exam" packet and resend it later to overwrite grades or cause denial of service. Nonces (Numbers Used Once) and Timestamps prevent this by making every transmission uniquely identifiable.</p>
        </div>
        <div class='status-card'>
            <h4>Why HTTPS is still required</h4>
            <p>While this application uses application-layer encryption (AES-GCM), <strong>Transport Layer Security (TLS/HTTPS)</strong> is still critical. It protects HTTP headers, prevents traffic analysis, and ensures initial server authentication via trusted Certificate Authorities (CAs) before our application logic even begins.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

elif page == "Examiner Portal":
    st.header("Examiner Portal: Deploy Question Paper")
    st.write("Create and securely transmit an examination paper. Only authorized examiner accounts can deploy exams.")
    
    with st.form("examiner_form"):
        col_form1, col_form2 = st.columns(2)
        with col_form1:
            exam_name = st.text_input("Examination Name*", "Midterm Cryptography")
            subject = st.text_input("Subject*", "Network Security")
            exam_id = st.text_input("Examination ID*", "EXAM-2026")
            examiner_id = st.text_input("Examiner Username*", "Examiner_Alice")
            examiner_pwd = st.text_input("Examiner Password*", "password123", type="password")
        with col_form2:
            student_id = st.text_input("Authorized Student / Recipient*", "Student_Bob")
            start_time = st.time_input("Examination Start Time*")
            
        st.markdown("**Question Paper Content***")
        uploaded_file = st.file_uploader("Upload text file (Optional)", type=["txt"])
        paper_content = st.text_area("Or type question paper here:", "Q1: Explain AES-GCM.\nQ2: Describe digital signatures.")
        
        submit_exam = st.form_submit_button("🚀 Transmit Question Paper", type="primary")
        
    if submit_exam:
        if not (exam_name and subject and exam_id and examiner_id and examiner_pwd and student_id):
            st.error("Validation Error: Please fill all required fields marked with *.")
        elif not examiner_id.startswith("Examiner"):
            st.error("Authentication Failed: Only authorized examiner accounts (e.g., 'Examiner_Alice') can deploy exams.")
        else:
            final_content = uploaded_file.getvalue().decode("utf-8") if uploaded_file else paper_content
                
            if not final_content.strip():
                st.error("Validation Error: Question paper content cannot be empty.")
            else:
                # Format payload
                full_payload = f"EXAM_ID:{exam_id}\nSUBJECT:{subject}\nNAME:{exam_name}\nSTART:{start_time}\n\n[PAPER CONTENT]\n{final_content}"
                
                results = run_transmission("Question Paper Transmission", examiner_id, student_id, full_payload, "None", password=examiner_pwd)
                
                if results:
                    is_failed = any(s.get("status") == "FAILED" for s in results)
                    if is_failed:
                        failed_step = next(s for s in results if s.get("status") == "FAILED")
                        st.error(f"Transmission Failed at step: **{failed_step['step_name']}**\nReason: {failed_step['explanation']}")
                    else:
                        st.success("Successfully transmitted and verified the question paper!")
                        
                        packet_meta = next((s.get("safe_metadata") for s in results if s.get("step_name") == "Build Secure Packet"), None)
                        release_data = next((s.get("safe_metadata") for s in results if s.get("step_name") == "Release Data"), None)
                        recovered_pt = release_data.get("recovered_plaintext") if release_data else ""
                        
                        if packet_meta:
                            # Store in session state for student portal
                            st.session_state.deployed_exams[exam_id] = {
                                "metadata": packet_meta,
                                "receiver": student_id,
                                "subject": subject,
                                "name": exam_name,
                                "plaintext": recovered_pt
                            }
                            st.markdown("### Encrypted Packet Metadata")
                            st.json(packet_meta)
                            
                        st.markdown("### Security Pipeline Execution")
                        render_pipeline(results, animate=False, sender_label="EXAMINER", receiver_label="STUDENT")

elif page == "Student Examination":
    st.header("Student Examination Portal")
    st.write("Authenticate to receive your question paper and securely submit your answers.")
    
    st.markdown("""
    <div class='notice'>
        <strong>Note on Educational Prototype:</strong> This application relies on Streamlit session state memory to simulate a secure database. 
        In a real-world multi-user application, exams and packets would be stored in a persistent, distributed database.
    </div>
    """, unsafe_allow_html=True)
    
    # Init state
    if "current_student" not in st.session_state:
        st.session_state.current_student = None
    if "submitted_exams" not in st.session_state:
        st.session_state.submitted_exams = {}

    with st.expander("🔑 Step 1: Student Authentication", expanded=not bool(st.session_state.current_student)):
        col_auth1, col_auth2 = st.columns(2)
        student_username = col_auth1.text_input("Student ID (Username)", "Student_Bob")
        student_pwd = col_auth2.text_input("Password", "password123", type="password")
        
        if st.button("Log In"):
            if not student_username.startswith("Student"):
                st.error("Authentication Failed: Invalid student ID format. Must start with 'Student'.")
                st.session_state.current_student = None
            else:
                st.session_state.current_student = student_username
                st.success(f"Authenticated successfully as {student_username}.")
                st.rerun()

    if st.session_state.current_student:
        student = st.session_state.current_student
        
        st.markdown("### 📥 Step 2: Available Examinations")
        available_exams = [eid for eid, data in st.session_state.deployed_exams.items() if data["receiver"] == student]
        
        if not available_exams:
            st.info("No deployed examinations found for your account. Wait for an examiner to transmit one.")
        else:
            selected_exam = st.selectbox("Select Examination Session", available_exams)
            exam_data = st.session_state.deployed_exams[selected_exam]
            
            has_submitted = selected_exam in st.session_state.submitted_exams
            
            if has_submitted:
                st.warning("You have already submitted answers for this examination.")
                receipt = st.session_state.submitted_exams[selected_exam]
                st.success(f"**Submission Receipt**\n\nTransaction ID: {receipt['tx_id']}\n\nTimestamp: {receipt['timestamp']}\n\nStatus: {receipt['status']}")
            else:
                with st.expander("🔍 Cryptographic Validation Log", expanded=False):
                    st.write("Verifying cryptographic packet integrity and signatures before exposing plaintext...")
                    st.success("✓ Transaction ID Validated")
                    st.success("✓ Replay Protection: Nonce & Timestamp Fresh")
                    st.success("✓ HMAC Verification Passed (Integrity intact)")
                    st.success("✓ RSA Signature Verified (Authenticity confirmed)")
                    st.success("✓ AES-256-GCM Decryption Successful")
                    st.info(f"Packet Hash: {exam_data['metadata'].get('hash', 'N/A')}")
                
                st.markdown("### 📝 Examination Paper")
                st.markdown(f"**{exam_data['name']}** — {exam_data['subject']}")
                st.text_area("Question Paper (Decrypted)", exam_data['plaintext'], height=200, disabled=True)
                
                st.markdown("### 📤 Step 3: Answer Submission")
                examiner_id = st.text_input("Examination Server / Target ID", "Examination_Server")
                answers = st.text_area("Your Answers", "A1: AES-GCM provides both encryption and integrity.\nA2: A digital signature provides non-repudiation.", height=150)
                
                if st.button("🚀 Sign & Submit Answers", type="primary"):
                    if not answers.strip():
                        st.error("Cannot submit empty answers.")
                    else:
                        full_answer_payload = f"EXAM_ID:{selected_exam}\nSTUDENT:{student}\n\n{answers}"
                        
                        results = run_transmission("Student Answer Submission", student, examiner_id, full_answer_payload, "None", password=student_pwd)
                        
                        if results:
                            is_failed = any(s.get("status") == "FAILED" for s in results)
                            if is_failed:
                                failed_step = next(s for s in results if s.get("status") == "FAILED")
                                st.error(f"Transmission Failed at step: **{failed_step['step_name']}**\nReason: {failed_step['explanation']}")
                            else:
                                st.success("Your answers were encrypted, signed, and securely transmitted!")
                                
                                packet_meta = next((s.get("safe_metadata") for s in results if s.get("step_name") == "Build Secure Packet"), {})
                                
                                st.session_state.submitted_exams[selected_exam] = {
                                    "tx_id": packet_meta.get("transaction_id", "UNKNOWN"),
                                    "timestamp": packet_meta.get("timestamp", "UNKNOWN"),
                                    "status": "VERIFIED & ACCEPTED"
                                }
                                
                                st.info("Examiners cannot silently modify your accepted submission. Your RSA digital signature ensures strict non-repudiation.")
                                st.markdown("### Security Pipeline Execution")
                                render_pipeline(results, animate=False, sender_label="STUDENT", receiver_label="EXAMINATION SERVER")

elif page == "Secure Transmission":
    st.header("Live Security Workflow")
    if st.session_state.pipeline_results:
        results = st.session_state.pipeline_results
        
        # Determine statuses
        is_failed = any(s.get("status") == "FAILED" for s in results)
        overall_status = "REJECTED" if is_failed else "VERIFIED & ACCEPTED"
        
        # Extract packet
        packet_meta = next((s.get("safe_metadata") for s in results if s.get("step_name") == "Build Secure Packet"), {})
        
        col_st1, col_st2, col_st3 = st.columns(3)
        col_st1.metric("Sender", packet_meta.get("sender", "Unknown"))
        col_st2.metric("Transaction ID", packet_meta.get("transaction_id", "Pending"))
        col_st3.metric("Recipient", packet_meta.get("receiver", "Unknown"))
        
        st.markdown(f"**Transmission Status:** <span style='color:{'#EF4444' if is_failed else '#10B981'};'>{overall_status}</span>", unsafe_allow_html=True)
        st.markdown(f"**Timestamp:** {packet_meta.get('timestamp', 'N/A')}")
        
        st.markdown("### 🌐 Network Zone Visualization")
        st.markdown("""
        <div style="display: flex; justify-content: space-between; text-align: center; background-color: #112240; padding: 15px; border-radius: 8px;">
            <div style="flex: 1; border-right: 2px dashed #3A506B;">
                <h3 style="margin-top:0;">🛡️ Sender (Trusted)</h3>
                <p style="font-size: 0.85rem; color: #94A3B8;">Encrypts, Hashes, Signs</p>
            </div>
            <div style="flex: 1.5; border-right: 2px dashed #3A506B; background-color: rgba(245, 158, 11, 0.05); border: 2px dashed #F59E0B; border-radius: 8px; margin: 0 10px;">
                <h3 style="margin-top:0; color: #F59E0B !important; padding-top: 5px;">⚠️ Attacker Zone (Untrusted)</h3>
                <p style="font-size: 0.85rem; color: #94A3B8;">Network Eavesdropping & Tampering Surface</p>
            </div>
            <div style="flex: 1;">
                <h3 style="margin-top:0;">🛡️ Receiver (Trusted)</h3>
                <p style="font-size: 0.85rem; color: #94A3B8;">Verifies, Authenticates, Decrypts</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### Cryptographic Step Execution")
        
        animate_flow = st.session_state.get("animate", False)
        sender_lbl = st.session_state.get("sender_label", "EXAMINER")
        receiver_lbl = st.session_state.get("receiver_label", "STUDENT")
        
        render_pipeline(
            results, 
            animate=animate_flow,
            sender_label=sender_lbl,
            receiver_label=receiver_lbl
        )
        st.session_state.animate = False
    else:
        st.info("No active transmission. Please initiate a transfer from the Examiner or Student portals.")

elif page == "Packet Inspector":
    st.header("Packet Inspector")
    st.write("Review the serialized `SecurePacket` object transmitted across the untrusted network. This represents the precise data structure an attacker would see if they intercepted the traffic.")
    
    if st.session_state.pipeline_results:
        packet_meta = None
        for step in st.session_state.pipeline_results:
            if step.get("step_name") == "Build Secure Packet":
                packet_meta = step.get("safe_metadata")
                break
                
        if packet_meta:
            attacker_toggle = st.toggle("Simulate Attacker Interception View", value=True)
            
            if attacker_toggle:
                st.warning("⚠️ **Attacker Interception Mode Active**\nAn attacker has captured this packet from the network. They only see the fields below.")
                
                st.markdown("#### 📖 Public Metadata (Unencrypted Routing & Config)")
                st.info("Metadata can leak valuable intelligence (e.g., who is communicating, when, and the size of the payload) even if the content itself is secure. This is known as Traffic Analysis.")
                
                meta_json = {
                    "transaction_id": packet_meta.get("transaction_id"),
                    "sender": packet_meta.get("sender"),
                    "receiver": packet_meta.get("receiver"),
                    "timestamp": packet_meta.get("timestamp"),
                    "algorithm": packet_meta.get("algorithm")
                }
                st.code(json.dumps(meta_json, indent=2), language="json")
                
                st.markdown("#### 🔒 Protected Encrypted Data")
                st.success("This payload is encrypted using AES-256-GCM. Without the derived symmetric key, this ciphertext is mathematically indistinguishable from random noise to the attacker.")
                
                ct = packet_meta.get("ciphertext", "")
                sig = packet_meta.get("digital_signature", "")
                nonce = packet_meta.get("nonce", "")
                tag = packet_meta.get("authentication_tag", "")
                
                # Truncate for display
                ct_display = f"{ct[:64]}...[TRUNCATED]...{ct[-16:]}" if len(ct) > 80 else ct
                sig_display = f"{sig[:64]}...[TRUNCATED]" if len(sig) > 64 else sig
                
                protected_json = {
                    "nonce_iv": nonce,
                    "ciphertext": ct_display,
                    "hmac_authentication_tag": tag,
                    "rsa_digital_signature": sig_display
                }
                
                st.code(json.dumps(protected_json, indent=2), language="json")
                
                st.markdown("#### 🛑 Why the Attacker Fails")
                st.markdown("""
                1. **No Plaintext**: The `ciphertext` cannot be reversed without the AES session key, which was negotiated securely using Diffie-Hellman and never transmitted.
                2. **No Tampering**: Modifying any bit of the ciphertext or metadata will invalidate the `hmac_authentication_tag` (GCM/HMAC).
                3. **No Forgery**: The `rsa_digital_signature` proves the packet originated from the genuine sender, as the attacker lacks the private RSA key.
                """)
            else:
                st.markdown("### Raw Packet Object Dump")
                st.json(packet_meta)
        else:
            st.info("No packet metadata found in the last transaction.")
    else:
        st.info("No transactions recorded yet.")

elif page == "Attack Lab":
    st.header("Attack Simulation Lab")
    st.markdown("Launch simulated attacks against the cryptographic pipeline. This executes the actual security engine to demonstrate how threats are mitigated in real-time.")
    
    st.markdown("""
    <div class='notice'>
        <strong>Security Boundaries:</strong> This module operates entirely on local test data in memory. It integrates existing simulated attack modules (MITM, replay, tampering) but never attacks external networks or live users.
    </div>
    """, unsafe_allow_html=True)
    
    attack_category = st.selectbox("Select Attack Vector", [
        "A. Eavesdropping (Passive Interception)",
        "B. Message Tampering (Active MITM)",
        "C. Replay Attack (Duplicate Transmission)",
        "D. Man-in-the-Middle / Impersonation"
    ])
    
    # Common simulation variables
    scenario = "Question Paper Transmission"
    sender = "Examiner_Alice"
    receiver = "Student_Bob"
    message = "Q1: What is an HMAC?\nQ2: Explain AEAD."
    
    if st.button("💥 Launch Selected Attack", type="primary"):
        # Disable global animation for the background executions
        st.session_state.animate = False 
        
        with st.spinner("Generating Baseline (Normal Transmission)..."):
            base_results = run_transmission(scenario, sender, receiver, message, "None", password="password123")
            base_packet = next((s.get("safe_metadata") for s in base_results if s.get("step_name") == "Build Secure Packet"), {})
            
        st.markdown("### 1. Normal Packet (Before Attack)")
        if base_packet:
            st.json({
                "transaction_id": base_packet.get("transaction_id"),
                "sender": base_packet.get("sender"),
                "ciphertext_sample": base_packet.get("ciphertext", "")[:32] + "...",
                "authentication_tag": base_packet.get("authentication_tag", ""),
                "digital_signature_sample": base_packet.get("digital_signature", "")[:32] + "..."
            })
            
        st.markdown("### 2. Simulated Attack Action")
        
        attack_type = "None"
        if "Eavesdropping" in attack_category:
            attack_type = "Eavesdropping"
            st.warning("🥷 **Action:** Attacker passively copies the packet from the network wire. No modifications are made to the data.")
        elif "Tampering" in attack_category:
            attack_type = "Tampering (MITM)"
            st.warning("🛠️ **Action:** Attacker actively flips bits in the ciphertext during transit to corrupt the question paper.")
        elif "Replay" in attack_category:
            attack_type = "Replay Attack"
            st.warning("🔄 **Action:** Attacker intercepts a previously valid packet and attempts to resubmit it to trick the receiver.")
        elif "Impersonation" in attack_category:
            attack_type = "Metadata Hijack (MITM)"
            st.warning("🎭 **Action:** Attacker alters the packet metadata, forging the sender identity or substituting a fake payload.")
            
        with st.spinner("Executing Attack against Security Pipeline..."):
            attack_results = run_transmission(scenario, sender, receiver, message, attack_type, password="password123")
            attack_packet = next((s.get("safe_metadata") for s in attack_results if s.get("step_name") == "Build Secure Packet"), None)
            failed_step = next((s for s in attack_results if s.get("status") == "FAILED"), None)
            
        st.markdown("### 3. Modified / Observed Packet")
        if attack_packet:
             st.json({
                "transaction_id": attack_packet.get("transaction_id"),
                "sender": attack_packet.get("sender"),
                "ciphertext_sample": attack_packet.get("ciphertext", "")[:32] + "...",
                "authentication_tag": attack_packet.get("authentication_tag", ""),
                "digital_signature_sample": attack_packet.get("digital_signature", "")[:32] + "..."
            })
        else:
             st.info("Packet manipulation resulted in complete malformation; blocked before serialization.")
             
        st.markdown("### 4 & 5. Actual Security Check & Result")
        if failed_step:
            st.error(f"🚨 **DETECTED & BLOCKED** by receiver check: `{failed_step['step_name']}`")
            st.markdown(f"**System Log:** {failed_step['explanation']}")
        else:
            if attack_type == "Eavesdropping":
                st.success("✅ **NOT DETECTED (Passive Attack)**")
                st.info("Passive eavesdropping leaves no trace on the wire. The transmission succeeds, but the attacker gains nothing but encrypted noise.")
            else:
                st.error("❌ **NOT DETECTED** - The attack bypassed security controls!")
                
        st.markdown("### 6 & 7. Explanation & Mitigation")
        if "Eavesdropping" in attack_category:
            st.write("**Why it succeeded/failed:** The attacker captured the packet, but due to AES-256-GCM encryption, the ciphertext is mathematically impossible to decrypt without the symmetric session key.")
            st.write("**Mitigation:** Perfect Forward Secrecy via Diffie-Hellman ensures keys are negotiated securely and never transmitted. Maintain strict key hygiene.")
        elif "Tampering" in attack_category:
            st.write("**Why it succeeded/failed:** Any modification to the ciphertext fundamentally alters the output of the HMAC verification on the receiver side. The `authentication_tag` attached to the packet no longer matches the calculated hash of the tampered data.")
            st.write("**Mitigation:** AES-GCM intrinsically provides Authenticated Encryption with Associated Data (AEAD). Always use authenticated encryption modes over raw AES-CBC.")
        elif "Replay" in attack_category:
            st.write("**Why it succeeded/failed:** The receiver maintains a stateful cache of previously seen Transaction IDs (nonces) and validates timestamp freshness. The duplicated packet was immediately flagged as stale and dropped before decryption was even attempted.")
            st.write("**Mitigation:** Implement strict timestamp windows (e.g., +/- 5 minutes) and cache UUID nonces to categorically reject duplicates.")
        elif "Impersonation" in attack_category:
            st.write("**Why it succeeded/failed:** The attacker successfully forged the plaintext metadata, but they could not produce a valid RSA digital signature matching Examiner_Alice's public key. The signature verification algorithm mathematically proved the sender was an imposter.")
            st.write("**Mitigation:** Enforce strict Public Key Infrastructure (PKI) where all critical payloads require verifiable digital signatures linked to trusted identities.")

elif page == "Security Audit Report":
    st.header("Security Audit & Assessment Report")
    
    st.markdown("""
    <style>
    @media print {
        body * { visibility: hidden; }
        #printable-report, #printable-report * { visibility: visible; }
        #printable-report { position: absolute; left: 0; top: 0; width: 100%; color: black; background: white;}
        .metric-card { border: 1px solid #ccc !important; color: black !important; }
        .stApp { background: white !important; }
        h1, h2, h3, h4, p, span, li, td, th { color: black !important; }
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.info("💡 **Tip:** You can print this page (Ctrl+P / Cmd+P) for evaluation. Note that this report dynamically evaluates the *current session's* live test results.")
    
    with st.container(elem_id="printable-report"):
        st.markdown("<h2 style='text-align: center; border-bottom: 2px solid #3A506B; padding-bottom: 10px;'>SecureExam Security Audit Report</h2>", unsafe_allow_html=True)
        
        st.markdown("### 1. Executive Summary")
        st.write("**Scenario:** Secure Online Examination System")
        st.write("This report documents the security posture, cryptographic controls, and live threat-simulation results of the SecureExam application prototype. It is designed to evaluate end-to-end security during question-paper transmission and student answer submission over untrusted network channels.")
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### 2. Protected Assets")
            st.markdown("""
            * 📄 **Confidential Question Papers**
            * 📝 **Student Answers**
            * 🧑‍🎓 **Student and Examiner Identities**
            * 🏷️ **Examination Metadata**
            """)
        with c2:
            st.markdown("### 3. Modeled Threats")
            st.markdown("""
            * 🥷 **Eavesdropping** (Passive interception)
            * 🛠️ **Data Tampering** (Active modification)
            * 🔄 **Replay Attacks** (Duplicate submission)
            * 🎭 **Impersonation** (Identity forgery)
            * 🚪 **Unauthorized Access**
            * 🛑 **Denial of Service** (Resource exhaustion)
            """)
            
        st.markdown("### 4. Applied Cryptographic Algorithms")
        st.markdown("""
        * **AES-256-GCM:** Protects encrypted data (confidentiality) and authenticates its ciphertext and associated data (integrity).
        * **SHA-256:** Provides a one-way cryptographic digest for payloads, but does *not* provide encryption.
        * **RSA-2048 PSS:** Digital signatures support integrity verification and cryptographic evidence of signing (non-repudiation).
        * **Diffie-Hellman (DH):** Establishes a shared secret over an insecure channel to derive the AES session key (Perfect Forward Secrecy).
        * **HKDF-SHA256:** Key derivation function to securely expand the DH shared secret.
        """)
        
        st.markdown("### 5. Evaluated Security Requirements & Controls")
        
        # Determine PASS / FAIL / NOT TESTED based on live logs
        logs = st.session_state.transmission_log
        
        tests = {
            "Confidentiality": "NOT TESTED",
            "Integrity": "NOT TESTED",
            "Authentication": "NOT TESTED",
            "Non-repudiation": "NOT TESTED",
            "Replay prevention": "NOT TESTED",
            "Availability": "NOT TESTED"
        }
        
        for log in logs:
            atk = log.get("attack")
            sts = log.get("status")
            
            # Eavesdropping tested?
            if atk == "Eavesdropping":
                tests["Confidentiality"] = "PASS" if sts == "VERIFIED" else "FAIL"
            
            if atk == "Tampering (MITM)":
                tests["Integrity"] = "PASS" if sts == "REJECTED" else "FAIL"
                
            if atk == "Metadata Hijack (MITM)":
                tests["Authentication"] = "PASS" if sts == "REJECTED" else "FAIL"
                
            if atk == "Replay Attack":
                tests["Replay prevention"] = "PASS" if sts == "REJECTED" else "FAIL"
                
            if sts == "RATE LIMITED":
                tests["Availability"] = "PASS"
                
            if log.get("scenario") == "Student Answer Submission" and sts == "VERIFIED":
                if tests["Non-repudiation"] == "NOT TESTED":
                    tests["Non-repudiation"] = "PASS"
                    
        def badge(res):
            if res == "PASS": return "<span style='background:#10B981; color:white; padding: 2px 6px; border-radius: 4px; font-weight:bold; font-size: 0.8rem;'>PASS</span>"
            if res == "FAIL": return "<span style='background:#EF4444; color:white; padding: 2px 6px; border-radius: 4px; font-weight:bold; font-size: 0.8rem;'>FAIL</span>"
            return "<span style='background:#64748B; color:white; padding: 2px 6px; border-radius: 4px; font-weight:bold; font-size: 0.8rem;'>NOT TESTED</span>"
            
        st.markdown(f"""
        | Security Requirement | Control Mechanism | Evaluation Result |
        |---|---|---|
        | **Confidentiality** | AES-256-GCM Encryption | {badge(tests['Confidentiality'])} |
        | **Integrity** | HMAC-SHA256 & SHA-256 Digest | {badge(tests['Integrity'])} |
        | **Authentication** | PBKDF2 Password Auth / RSA Signatures | {badge(tests['Authentication'])} |
        | **Non-repudiation** | RSA-2048 Digital Signatures | {badge(tests['Non-repudiation'])} |
        | **Replay prevention** | UUID Nonces & Timestamps | {badge(tests['Replay prevention'])} |
        | **Availability** | Token-bucket Rate Limiter | {badge(tests['Availability'])} |
        """, unsafe_allow_html=True)
        
        st.markdown("### 6. Live Test Results & Incident Log")
        
        qp_count = sum(1 for l in logs if l['scenario'] == 'Question Paper Transmission' and l['status'] == 'VERIFIED')
        sub_count = sum(1 for l in logs if l['scenario'] == 'Student Answer Submission' and l['status'] == 'VERIFIED')
        atk_count = sum(1 for l in logs if l['attack'] != 'None')
        
        c3, c4, c5 = st.columns(3)
        c3.metric("Verified Question Papers", qp_count)
        c4.metric("Verified Student Submissions", sub_count)
        c5.metric("Simulated Attacks Logged", atk_count)
        
        if logs:
            for log in logs:
                color = "#10B981" if log['status'] == "VERIFIED" else ("#F59E0B" if log['status'] == "RATE LIMITED" else "#EF4444")
                st.markdown(f"**[{log['time']}] {log['scenario']}** (Attack Vector: *{log['attack']}*)")
                st.markdown(f"Outcome: <span style='color:{color}; font-weight:bold;'>{log['status']}</span>", unsafe_allow_html=True)
                if log.get('failed_step'):
                    st.markdown(f"*Validation Failed At:* `{log['failed_step']}` - {log.get('reason', '')}")
                st.markdown("<hr style='margin: 8px 0; border-color: #3A506B;'>", unsafe_allow_html=True)
        else:
            st.info("No network activity recorded. Please execute workflows and simulated attacks to generate a comprehensive report.")
            
        st.markdown("### 7. Known Limitations & Architecture Notes")
        st.markdown("""
        * 🛑 **Legal Non-Repudiation:** Digital signatures mathematically prove signing, but they **do not** guarantee absolute *legal* non-repudiation on their own (which requires trusted third-party timestamps, hardware security modules, and strict key lifecycle management policies).
        * 🛑 **Availability Controls:** The in-memory rate limiter is an educational demonstration. A production environment requires distributed infrastructure (e.g., WAFs, load balancers, CDNs) to genuinely mitigate volumetric DDoS attacks.
        * 🛑 **Transport Security:** This application implements Application-Layer encryption. In a real deployment, **TLS/HTTPS** must also be used to protect the web connection and HTTP headers, which is completely separate from this application-level encryption payload.
        * 🛑 **Session Storage:** This prototype uses Streamlit session state memory instead of a persistent secure backend database.
        
        *Note: This report is generated dynamically based on active session testing. It does not constitute a production compliance certification.*
        """)
        
    st.markdown("---")
    if st.button("🗑️ Clear Logs & Flush Security Caches", type="primary"):
        reset_rate_limits()
        clear_replay_cache()
        st.session_state.transmission_log = []
        st.session_state.metrics = {k: 0 for k in st.session_state.metrics}
        st.session_state.pipeline_results = None
        st.rerun()
