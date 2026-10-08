import streamlit as st
import time

def get_status_styling(status: str) -> tuple:
    """Returns the icon, color, and display text based on the execution status."""
    status = status.upper()
    if status == "FAILED":
        return "❌", "#EF4444", "REJECTED"
    if status in ["SUCCESS", "SECURE"]:
        return "✓", "#10B981", "VERIFIED"
    if "ATTACK" in status or "SIMULATED" in status:
        return "⚠️", "#F59E0B", "ATTACK DETECTED"
    if "TRANSIT" in status:
        return "🌐", "#3B82F6", "IN TRANSIT"
    return "⏳", "#94A3B8", "PENDING"

def render_pipeline(steps_log: list, animate: bool = False, sender_label: str = "EXAMINER", receiver_label: str = "STUDENT"):
    """
    Renders the interactive visual security flow in Streamlit.
    Takes the structured steps_log from the central workflow engine (security/workflow.py)
    and renders it as a professional cybersecurity dashboard pipeline.
    """
    
    # Inject custom CSS for a dark navy cybersecurity dashboard layout
    st.markdown("""
        <style>
        .pipeline-card {
            background-color: #112240;
            border-radius: 8px;
            padding: 15px 20px;
            margin-bottom: 5px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
            border-left: 5px solid #334155;
            transition: all 0.3s ease;
            color: #E2E8F0;
            font-family: monospace;
        }
        .pipeline-card:hover {
            transform: translateX(5px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.4);
        }
        .pipeline-title {
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 4px;
            color: #E2E8F0;
            letter-spacing: 0.5px;
        }
        .pipeline-desc {
            font-size: 0.9rem;
            color: #94A3B8;
            margin-bottom: 8px;
        }
        .pipeline-algo {
            font-size: 0.75rem;
            color: #64FFDA;
            background-color: rgba(100, 255, 218, 0.1);
            padding: 3px 8px;
            border-radius: 4px;
            display: inline-block;
            margin-bottom: 8px;
            border: 1px solid rgba(100, 255, 218, 0.2);
        }
        .pipeline-status {
            font-size: 0.85rem;
            font-weight: 800;
            letter-spacing: 1px;
        }
        .pipeline-arrow {
            text-align: center;
            font-size: 1.8rem;
            color: #334155;
            margin: -5px 0px;
        }
        .rejection-path {
            border: 2px dashed #EF4444;
            padding: 15px;
            border-radius: 8px;
            background-color: rgba(239, 68, 68, 0.05);
            margin-top: 10px;
        }
        .attacker-zone {
            border: 2px dashed #F59E0B;
            background-color: rgba(245, 158, 11, 0.05);
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            position: relative;
        }
        .attacker-zone::before {
            content: '⚠️ UNTRUSTED ATTACKER ZONE ⚠️';
            position: absolute;
            top: -12px;
            left: 20px;
            background-color: #0B132B;
            color: #F59E0B;
            font-size: 0.8rem;
            font-weight: bold;
            padding: 0 10px;
            border: 2px solid #F59E0B;
            border-radius: 4px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    total_steps = len(steps_log)
    
    # Progress UI
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    if not animate:
        progress_bar.progress(100)
        status_text.markdown(f"**Workflow Complete: {total_steps}/{total_steps} Steps**")

    # Create a dedicated container for drawing the cards
    cards_container = st.container()
    
    with cards_container:
        # 1. ALWAYS SHOW THE SENDER NODE FIRST
        st.markdown(f"""
            <div class="pipeline-card" style="border-left-color: #10B981;">
                <div class="pipeline-title">👤 {sender_label.upper()}</div>
                <div class="pipeline-desc">Initiating the secure transaction.</div>
                <div class="pipeline-status" style="color: #10B981;">✓ COMPLETED</div>
            </div>
            <div class="pipeline-arrow">↓</div>
        """, unsafe_allow_html=True)
        
    if animate:
        time.sleep(0.4)
    
    # 2. ITERATE THROUGH THE PIPELINE LOG
    pipeline_halted = False
    
    for idx, step in enumerate(steps_log):
        
        current_step_num = idx + 1
        
        if animate:
            progress_pct = int((current_step_num / total_steps) * 100)
            progress_bar.progress(progress_pct)
            status_text.markdown(f"**Executing Stage {current_step_num}/{total_steps}: {step.get('step_name', '')}**")
            
        raw_status = step.get("status", "PENDING")
        title = step.get("step_name", "System Step").upper()
        explanation = step.get("explanation", "")
        algo = step.get("algorithm", None)
        safe_meta = step.get("safe_metadata", {})
        
        icon, color, display_status = get_status_styling(raw_status)
        is_err = display_status == "REJECTED"
        
        # Build HTML components
        algo_html = f'<div class="pipeline-algo">⚙️ {algo}</div>' if algo else ''
        
        html_card = f"""
            <div class="pipeline-card" style="border-left-color: {color};">
                <div class="pipeline-title">{icon} {title}</div>
                {algo_html}
                <div class="pipeline-desc">{explanation}</div>
                <div class="pipeline-status" style="color: {color};">{icon} {display_status}</div>
            </div>
        """
        
        with cards_container:
            if "UNTRUSTED" in title:
                st.markdown('<div class="attacker-zone">', unsafe_allow_html=True)
                
            st.markdown(html_card, unsafe_allow_html=True)
            
            # Expandable Safe Metadata
            if safe_meta:
                with st.expander("🔍 View Technical Metadata"):
                    st.json(safe_meta)
                    
            if "UNTRUSTED" in title:
                st.markdown('</div>', unsafe_allow_html=True)
                        
            # Draw the Arrow (if not the last step and not an error)
            if idx < len(steps_log) - 1 and not is_err:
                st.markdown('<div class="pipeline-arrow">↓</div>', unsafe_allow_html=True)
                
        if animate:
            time.sleep(0.6)
            
        # 3. IF THE PIPELINE FAILED (REJECTED), SHOW REJECTION PATH AND STOP
        if is_err:
            with cards_container:
                st.markdown(f"""
                    <div class="rejection-path">
                        <h4 style="color: #EF4444; margin-top: 0;">🚨 PIPELINE HALTED</h4>
                        <p style="color: #E2E8F0; margin-bottom: 0;">Validation failed at stage <b>{title}</b>. The SecurePacket has been rejected to prevent unauthorized data exposure.</p>
                    </div>
                """, unsafe_allow_html=True)
            pipeline_halted = True
            break
            
    if animate and not pipeline_halted:
        status_text.markdown(f"**Workflow Complete: {total_steps}/{total_steps} Stages**")
            
    # 4. IF IT FINISHED SUCCESSFULLY, SHOW THE RECEIVER NODE
    if not pipeline_halted and total_steps > 0:
        with cards_container:
            st.markdown('<div class="pipeline-arrow">↓</div>', unsafe_allow_html=True)
            st.markdown(f"""
                <div class="pipeline-card" style="border-left-color: #10B981;">
                    <div class="pipeline-title">🏢 {receiver_label.upper()}</div>
                    <div class="pipeline-desc">Verified payload securely delivered.</div>
                    <div class="pipeline-status" style="color: #10B981;">✓ RECEIVED</div>
                </div>
            """, unsafe_allow_html=True)
