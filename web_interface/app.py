"""
SAYN Web Interface - Enhanced Flask Application
"""
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_file
from flask_socketio import SocketIO, emit
import asyncio
import threading
import os
from datetime import datetime
from core.database import DatabaseManager
from core.config import Config
from core.utils import Logger, ReportGenerator

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'sayn-secret-key-change-in-production'
    
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    config = Config()
    db = DatabaseManager()
    logger = Logger()
    report_gen = ReportGenerator()
    
    # Make socketio available globally
    app.socketio = socketio
    
    @app.route('/')
    def index():
        """Main dashboard"""
        try:
            recent_scans = db.get_scan_history(limit=10)
            stats = db.get_vulnerability_stats()
            return render_template('dashboard.html', recent_scans=recent_scans, stats=stats)
        except Exception as e:
            logger.error(f"Error loading dashboard: {e}")
            flash('Error loading dashboard data', 'error')
            return render_template('dashboard.html', recent_scans=[], stats={})

    @app.route('/scan')
    def scan_page():
        """Scan configuration page"""
        return render_template('scan.html')

    @app.route('/history')
    def history_page():
        """Scan history page"""
        try:
            recent_scans = db.get_scan_history(limit=100)
            return render_template('history.html', scans=recent_scans)
        except Exception as e:
            logger.error(f"Error loading history: {e}")
            flash('Error loading scan history', 'error')
            return render_template('history.html', scans=[])

    @app.route('/dashboard')
    def dashboard():
        """Dashboard page - redirect to index"""
        return redirect(url_for('index'))

    @app.route('/api/dashboard/stats')
    def dashboard_stats():
        """Get dashboard statistics"""
        try:
            stats = {
                'total_scans': db.get_total_scans(),
                'completed_scans': db.get_completed_scans(),
                'failed_scans': db.get_failed_scans(),
                'total_vulnerabilities': db.get_total_vulnerabilities(),
                'high_risk_vulns': db.get_high_risk_vulnerabilities(),
                'medium_risk_vulns': db.get_medium_risk_vulnerabilities(),
                'low_risk_vulns': db.get_low_risk_vulnerabilities(),
                'recent_activity': db.get_recent_activity(limit=5)
            }
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scan/<int:scan_id>/progress')
    def scan_progress(scan_id):
        """Get scan progress"""
        try:
            progress = db.get_scan_progress(scan_id)
            if progress:
                return jsonify(progress)
            return jsonify({'error': 'Scan not found'}), 404
        except Exception as e:
            logger.error(f"Error getting scan progress: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scan', methods=['POST'])
    def start_scan():
        """Start a new security scan"""
        try:
            data = request.get_json()
            target = data.get('target')
            scan_name = data.get('scan_name', f'Scan {datetime.now().strftime("%Y-%m-%d %H:%M")}')
            scan_type = data.get('scan_type', 'web')
            scan_depth = data.get('scan_depth', 'normal')
            threads = data.get('threads', 10)
            timeout = data.get('timeout', 30)
            
            if not target:
                return jsonify({'error': 'Target is required'}), 400
            
            scan_id = db.create_scan_record(
                target=target,
                scan_name=scan_name,
                scan_type=scan_type,
                scan_depth=scan_depth,
                threads=threads,
                timeout=timeout
            )
            
            def run_async_scan():
                try:
                    from sayn import SAYN
                    sayn = SAYN()
                    
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        options = {
                            'threads': threads,
                            'timeout': timeout,
                            'verbose': False,
                            'scan_depth': scan_depth
                        }
                        
                        results = loop.run_until_complete(
                            sayn.scan_target(target, [scan_type], options)
                        )
                        
                        results['scan_id'] = scan_id
                        db.save_scan_results(results)
                        
                        app.socketio.emit('scan_completed', {
                            'scan_id': scan_id,
                            'results': results,
                            'status': 'completed'
                        })
                        
                    except Exception as e:
                        logger.error(f"Scan error: {e}")
                        app.socketio.emit('scan_error', {
                            'scan_id': scan_id,
                            'error': str(e),
                            'status': 'failed'
                        })
                    finally:
                        loop.close()
                        
                except Exception as e:
                    logger.error(f"Background scan error: {e}")
                    app.socketio.emit('scan_error', {
                        'scan_id': scan_id,
                        'error': str(e),
                        'status': 'failed'
                    })
            
            scan_thread = threading.Thread(target=run_async_scan)
            scan_thread.daemon = True
            scan_thread.start()
            
            return jsonify({
                'scan_id': scan_id,
                'status': 'started',
                'message': 'Scan started successfully'
            })
            
        except Exception as e:
            logger.error(f"Error starting scan: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scans')
    def get_scans():
        """Get scan history with filtering"""
        try:
            status = request.args.get('status')
            scan_type = request.args.get('scan_type')
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))
            
            scans = db.get_scan_history(
                limit=limit,
                offset=offset,
                status=status,
                scan_type=scan_type
            )
            return jsonify(scans)
        except Exception as e:
            logger.error(f"Error getting scans: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scan/<int:scan_id>')
    def get_scan_results(scan_id):
        """Get specific scan results"""
        try:
            results = db.get_scan_results(scan_id)
            if results:
                return jsonify(results)
            return jsonify({'error': 'Scan not found'}), 404
        except Exception as e:
            logger.error(f"Error getting scan results: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scan/<int:scan_id>/report')
    def download_report(scan_id):
        """Download scan report"""
        try:
            format_type = request.args.get('format', 'html')
            results = db.get_scan_results(scan_id)
            
            if not results:
                return jsonify({'error': 'Scan not found'}), 404
            
            report_path = report_gen.generate(results, format_type)
            return send_file(report_path, as_attachment=True)
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scan/<int:scan_id>', methods=['DELETE'])
    def delete_scan(scan_id):
        """Delete a scan"""
        try:
            success = db.delete_scan(scan_id)
            if success:
                return jsonify({'message': 'Scan deleted successfully'})
            return jsonify({'error': 'Scan not found'}), 404
        except Exception as e:
            logger.error(f"Error deleting scan: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/vulnerabilities')
    def get_vulnerabilities():
        """Get vulnerabilities with filtering"""
        try:
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))
            severity = request.args.get('severity')
            scan_id = request.args.get('scan_id')
            
            vulnerabilities = db.get_recent_vulnerabilities(limit)
            
            # Apply additional filtering if needed
            if severity:
                vulnerabilities = [v for v in vulnerabilities if v.get('severity') == severity]
            if scan_id:
                vulnerabilities = [v for v in vulnerabilities if v.get('scan_id') == int(scan_id)]
            
            return jsonify(vulnerabilities)
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {e}")
            return jsonify({'error': str(e)}), 500

    @app.socketio.on('connect')
    def handle_connect():
        """Handle WebSocket connection"""
        emit('connected', {'data': 'Connected to SAYN Scanner'})

    @app.socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection"""
        pass

    return app
