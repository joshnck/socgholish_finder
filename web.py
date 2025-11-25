from flask import Flask, render_template, request, jsonify, url_for, redirect
from db import get_db_session, Source, Indicator
from datetime import datetime, timedelta
import os
from sqlalchemy import or_

app = Flask(__name__)

@app.route('/')
def index():
    session = get_db_session()
    try:
        stats = {
            'total_indicators': session.query(Indicator).count(),
            'total_sources': session.query(Source).count(),
            'benign_sources': session.query(Source).filter_by(is_benign=True).count(),
            'malicious_sources': session.query(Source).filter(Source.is_benign == False).count(),
            'unanalyzed': session.query(Indicator).filter_by(is_analyzed=False).count()
        }
        return render_template('base.html', stats=stats)
    finally:
        session.close()

@app.route('/api/stats')
def get_stats():
    session = get_db_session()
    try:
        return jsonify({
            'total_indicators': session.query(Indicator).count(),
            'total_sources': session.query(Source).count(),
            'benign_sources': session.query(Source).filter_by(is_benign=True).count(),
            'malicious_sources': session.query(Source).filter(Source.is_benign == False).count(),
            'unanalyzed': session.query(Indicator).filter_by(is_analyzed=False).count()
        })
    finally:
        session.close()

@app.route('/api/sources')
def get_sources():
    session = get_db_session()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        is_benign = request.args.get('benign')
        
        query = session.query(Source)
        
        if is_benign == 'true':
            query = query.filter_by(is_benign=True)
        elif is_benign == 'false':
            query = query.filter(Source.is_benign == False)
        
        pagination = query.order_by(Source.last_checked.desc()).paginate(page=page, per_page=per_page)
        
        sources = [{
            'id': s.id,
            'url': s.url,
            'domain': s.domain,
            'first_seen': s.first_seen.isoformat(),
            'last_checked': s.last_checked.isoformat() if s.last_checked else None,
            'status_code': s.status_code,
            'is_benign': s.is_benign,
            'indicator_count': len(s.indicators)
        } for s in pagination.items]
        
        return jsonify({
            'sources': sources,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
    finally:
        session.close()

@app.route('/api/indicators')
def get_indicators():
    session = get_db_session()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        query = session.query(Indicator)
        
        # Filtering
        if request.args.get('analyzed') == 'false':
            query = query.filter_by(is_analyzed=False)
        if request.args.get('stage'):
            query = query.filter_by(stage=request.args.get('stage'))
        
        # Pagination
        pagination = query.order_by(Indicator.first_seen.desc()).paginate(page=page, per_page=per_page)
        
        indicators = [{
            'id': i.id,
            'snippet': i.snippet_text[:500] + '...' if len(i.snippet_text) > 500 else i.snippet_text,
            'snippet_text': i.snippet_text,
            'stage': i.stage,
            'detection_method': i.detection_method,
            'first_seen': i.first_seen.isoformat(),
            'source_url': i.source.url,
            'source_id': i.source_id,
            'is_analyzed': i.is_analyzed,
            'analysis_notes': i.analysis_notes or ''
        } for i in pagination.items]
        
        return jsonify({
            'indicators': indicators,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        })
    finally:
        session.close()

@app.route('/api/indicators/<int:id>', methods=['GET', 'POST'])
def indicator_detail(id):
    session = get_db_session()
    try:
        indicator = session.query(Indicator).get_or_404(id)
        
        if request.method == 'POST':
            data = request.get_json()
            if 'is_analyzed' in data:
                indicator.is_analyzed = data['is_analyzed']
            if 'analysis_notes' in data:
                indicator.analysis_notes = data['analysis_notes']
            session.commit()
        
        result = {
            'id': indicator.id,
            'snippet': indicator.snippet_text,
            'stage': indicator.stage,
            'detection_method': indicator.detection_method,
            'first_seen': indicator.first_seen.isoformat(),
            'last_seen': indicator.last_seen.isoformat(),
            'source_url': indicator.source.url,
            'source_id': indicator.source_id,
            'is_analyzed': indicator.is_analyzed,
            'analysis_notes': indicator.analysis_notes or ''
        }
        return jsonify(result)
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/sources/<int:id>/toggle_benign', methods=['POST'])
def toggle_benign(id):
    session = get_db_session()
    try:
        source = session.query(Source).get_or_404(id)
        source.is_benign = not source.is_benign
        source.last_checked = datetime.utcnow()
        session.commit()
        return jsonify({'success': True, 'is_benign': source.is_benign})
    except Exception as e:
        session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        session.close()

def main():
    # Ensure directories exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Start the Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
