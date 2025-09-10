from flask import Blueprint, render_template, request, jsonify
ids_bp = Blueprint('ids', __name__)

@ids_bp.route('/ids', methods=['GET', 'POST'])
def ids_home():
    detection_result = None
    if request.method == 'POST':
        # Example: get packet data from form
        packet_data = request.form.get('packet_data', '')
        # Simple IDS logic: look for suspicious keywords
        suspicious_keywords = ['attack', 'malware', 'exploit', 'virus', 'trojan']
        if any(keyword in packet_data.lower() for keyword in suspicious_keywords):
            detection_result = 'Intrusion Detected!'
        else:
            detection_result = 'No Intrusion Detected.'
        return render_template('ids.html', detection_result=detection_result, packet_data=packet_data)
    return render_template('ids.html', detection_result=detection_result)
