from flask import Blueprint, render_template, request
import socket

scanner_bp = Blueprint('scanner', __name__)

def scan_ports(target, ports):
    results = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((target, port))
            results.append({'port': port, 'status': 'open'})
        except (socket.timeout, ConnectionRefusedError):
            results.append({'port': port, 'status': 'closed'})
        except Exception as e:
            results.append({'port': port, 'status': f'error: {str(e)}'})
        finally:
            s.close()
    return results

@scanner_bp.route('/scan', methods=['GET', 'POST'])
def scan_home():
    results = None
    error = None
    if request.method == 'POST':
        target = request.form.get('target')
        port_range = request.form.get('ports')
        try:
            ports = []
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, end+1))
            else:
                ports = [int(p.strip()) for p in port_range.split(',')]
            results = scan_ports(target, ports)
        except Exception as e:
            error = f"Error: {str(e)}"
    return render_template('scan.html', results=results, error=error)
