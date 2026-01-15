"""
Traffic Monitoring Routes
Handles network traffic data collection and analysis
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from bson.objectid import ObjectId

traffic_bp = Blueprint('traffic', __name__)

@traffic_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_traffic_stats():
    """Get current traffic statistics"""
    try:
        db = current_app.config['DB']
        
        # Get time range
        hours = int(request.args.get('hours', 1))
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Aggregate traffic data
        pipeline = [
            {'$match': {'timestamp': {'$gte': start_time}}},
            {'$group': {
                '_id': None,
                'total_packets': {'$sum': '$packet_count'},
                'total_bytes': {'$sum': '$byte_count'},
                'avg_packet_rate': {'$avg': '$packet_rate'},
                'protocols': {'$push': '$protocol'}
            }}
        ]
        
        result = list(db.traffic.aggregate(pipeline))
        
        if result:
            stats = result[0]
            # Count protocol distribution
            protocols = stats.pop('protocols', [])
            protocol_count = {}
            for p in protocols:
                protocol_count[p] = protocol_count.get(p, 0) + 1
            
            stats['protocol_distribution'] = protocol_count
            stats.pop('_id', None)
        else:
            stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'avg_packet_rate': 0,
                'protocol_distribution': {}
            }
        
        # Get recent attack count
        attack_count = db.alerts.count_documents({
            'timestamp': {'$gte': start_time},
            'severity': {'$in': ['high', 'critical']}
        })
        
        stats['recent_attacks'] = attack_count
        
        return jsonify({
            'stats': stats,
            'time_range': f'Last {hours} hour(s)',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Get traffic stats error: {e}")
        return jsonify({'error': 'Failed to fetch traffic statistics'}), 500

@traffic_bp.route('/live', methods=['GET'])
@jwt_required()
def get_live_traffic():
    """Get live traffic data for charts"""
    try:
        db = current_app.config['DB']
        
        # Get last 20 data points (last minute)
        limit = int(request.args.get('limit', 20))
        
        traffic_data = list(db.traffic.find(
            {},
            {'_id': 0, 'timestamp': 1, 'packet_rate': 1, 'is_suspicious': 1}
        ).sort('timestamp', -1).limit(limit))
        
        # Reverse to get chronological order
        traffic_data.reverse()
        
        # Separate normal and suspicious traffic
        normal_traffic = []
        suspicious_traffic = []
        
        for data in traffic_data:
            point = {
                'time': data['timestamp'].strftime('%H:%M:%S'),
                'value': data.get('packet_rate', 0)
            }
            
            if data.get('is_suspicious', False):
                suspicious_traffic.append(point)
            else:
                normal_traffic.append(point)
        
        return jsonify({
            'normal': normal_traffic,
            'suspicious': suspicious_traffic,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Get live traffic error: {e}")
        return jsonify({'error': 'Failed to fetch live traffic data'}), 500

@traffic_bp.route('/history', methods=['GET'])
@jwt_required()
def get_traffic_history():
    """Get historical traffic data"""
    try:
        db = current_app.config['DB']
        
        # Parse query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        
        # Build query
        query = {}
        if start_date:
            query['timestamp'] = {'$gte': datetime.fromisoformat(start_date)}
        if end_date:
            if 'timestamp' in query:
                query['timestamp']['$lte'] = datetime.fromisoformat(end_date)
            else:
                query['timestamp'] = {'$lte': datetime.fromisoformat(end_date)}
        
        # Get total count
        total = db.traffic.count_documents(query)
        
        # Get paginated data
        skip = (page - 1) * per_page
        traffic_data = list(db.traffic.find(
            query,
            {'_id': 0}
        ).sort('timestamp', -1).skip(skip).limit(per_page))
        
        # Convert datetime to ISO format
        for data in traffic_data:
            if 'timestamp' in data:
                data['timestamp'] = data['timestamp'].isoformat()
        
        return jsonify({
            'data': traffic_data,
            'pagination': {
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            }
        }), 200
        
    except Exception as e:
        print(f"Get traffic history error: {e}")
        return jsonify({'error': 'Failed to fetch traffic history'}), 500

@traffic_bp.route('/submit', methods=['POST'])
@jwt_required()
def submit_traffic_data():
    """Submit new traffic data from agents"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['agent_id', 'packet_count', 'protocol']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400
        
        db = current_app.config['DB']
        
        # Prepare traffic document
        traffic_doc = {
            'agent_id': data['agent_id'],
            'packet_count': data['packet_count'],
            'byte_count': data.get('byte_count', 0),
            'packet_rate': data.get('packet_rate', 0),
            'protocol': data['protocol'],
            'src_ip': data.get('src_ip'),
            'dst_ip': data.get('dst_ip'),
            'src_port': data.get('src_port'),
            'dst_port': data.get('dst_port'),
            'is_suspicious': data.get('is_suspicious', False),
            'ml_confidence': data.get('ml_confidence', 0.0),
            'features': data.get('features', {}),
            'timestamp': datetime.utcnow()
        }
        
        # Insert traffic data
        result = db.traffic.insert_one(traffic_doc)
        
        return jsonify({
            'message': 'Traffic data submitted successfully',
            'id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        print(f"Submit traffic data error: {e}")
        return jsonify({'error': 'Failed to submit traffic data'}), 500

@traffic_bp.route('/export', methods=['GET'])
@jwt_required()
def export_traffic_data():
    """Export traffic data to CSV"""
    try:
        import csv
        from io import StringIO
        
        db = current_app.config['DB']
        
        # Get query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = {}
        if start_date:
            query['timestamp'] = {'$gte': datetime.fromisoformat(start_date)}
        if end_date:
            if 'timestamp' in query:
                query['timestamp']['$lte'] = datetime.fromisoformat(end_date)
            else:
                query['timestamp'] = {'$lte': datetime.fromisoformat(end_date)}
        
        # Fetch data
        traffic_data = list(db.traffic.find(query).sort('timestamp', -1).limit(10000))
        
        # Create CSV
        output = StringIO()
        if traffic_data:
            fieldnames = ['timestamp', 'agent_id', 'packet_count', 'byte_count', 
                         'protocol', 'src_ip', 'dst_ip', 'is_suspicious', 'ml_confidence']
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for data in traffic_data:
                row = {
                    'timestamp': data.get('timestamp', '').isoformat() if isinstance(data.get('timestamp'), datetime) else '',
                    'agent_id': data.get('agent_id', ''),
                    'packet_count': data.get('packet_count', 0),
                    'byte_count': data.get('byte_count', 0),
                    'protocol': data.get('protocol', ''),
                    'src_ip': data.get('src_ip', ''),
                    'dst_ip': data.get('dst_ip', ''),
                    'is_suspicious': data.get('is_suspicious', False),
                    'ml_confidence': data.get('ml_confidence', 0.0)
                }
                writer.writerow(row)
        
        csv_data = output.getvalue()
        
        return jsonify({
            'data': csv_data,
            'filename': f'garudarush_traffic_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
        }), 200
        
    except Exception as e:
        print(f"Export traffic data error: {e}")
        return jsonify({'error': 'Failed to export traffic data'}), 500