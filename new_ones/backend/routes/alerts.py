"""
Alerts Routes
Handles security alerts and notifications
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from bson.objectid import ObjectId

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/', methods=['GET'])
@jwt_required()
def get_alerts():
    """Get alerts with filtering and pagination"""
    try:
        db = current_app.config['DB']
        
        # Parse query parameters
        severity = request.args.get('severity')  # low, medium, high, critical
        status = request.args.get('status')  # active, acknowledged, resolved
        attack_type = request.args.get('attack_type')
        limit = int(request.args.get('limit', 50))
        page = int(request.args.get('page', 1))
        
        # Build query
        query = {}
        
        if severity:
            query['severity'] = severity
        
        if status:
            query['status'] = status
        
        if attack_type:
            query['attack_type'] = attack_type
        
        # Get recent alerts (last 7 days by default)
        start_time = datetime.utcnow() - timedelta(days=7)
        query['timestamp'] = {'$gte': start_time}
        
        # Get total count
        total = db.alerts.count_documents(query)
        
        # Get paginated alerts
        skip = (page - 1) * limit
        alerts = list(db.alerts.find(
            query
        ).sort('timestamp', -1).skip(skip).limit(limit))
        
        # Format alerts
        alert_list = []
        for alert in alerts:
            alert_list.append({
                'id': str(alert['_id']),
                'attack_type': alert.get('attack_type', 'Unknown'),
                'severity': alert.get('severity', 'medium'),
                'status': alert.get('status', 'active'),
                'source_ip': alert.get('source_ip'),
                'destination_ip': alert.get('destination_ip'),
                'confidence': alert.get('confidence', 0.0),
                'packet_count': alert.get('packet_count', 0),
                'description': alert.get('description', ''),
                'timestamp': alert['timestamp'].isoformat(),
                'acknowledged_by': alert.get('acknowledged_by'),
                'acknowledged_at': alert.get('acknowledged_at').isoformat() if alert.get('acknowledged_at') else None,
                'notes': alert.get('notes', '')
            })
        
        return jsonify({
            'alerts': alert_list,
            'pagination': {
                'total': total,
                'page': page,
                'limit': limit,
                'total_pages': (total + limit - 1) // limit
            }
        }), 200
        
    except Exception as e:
        print(f"Get alerts error: {e}")
        return jsonify({'error': 'Failed to fetch alerts'}), 500

@alerts_bp.route('/create', methods=['POST'])
@jwt_required()
def create_alert():
    """Create a new security alert"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['attack_type', 'severity']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field} is required'}), 400
        
        db = current_app.config['DB']
        
        # Prepare alert document
        alert_doc = {
            'attack_type': data['attack_type'],
            'severity': data['severity'],
            'status': 'active',
            'source_ip': data.get('source_ip'),
            'destination_ip': data.get('destination_ip'),
            'source_port': data.get('source_port'),
            'destination_port': data.get('destination_port'),
            'protocol': data.get('protocol'),
            'confidence': data.get('confidence', 0.0),
            'packet_count': data.get('packet_count', 0),
            'byte_count': data.get('byte_count', 0),
            'description': data.get('description', ''),
            'agent_id': data.get('agent_id'),
            'features': data.get('features', {}),
            'detection_time': data.get('detection_time', 0),
            'timestamp': datetime.utcnow(),
            'attack_detected': True
        }
        
        # Insert alert
        result = db.alerts.insert_one(alert_doc)
        
        return jsonify({
            'message': 'Alert created successfully',
            'alert_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        print(f"Create alert error: {e}")
        return jsonify({'error': 'Failed to create alert'}), 500

@alerts_bp.route('/<alert_id>/acknowledge', methods=['POST'])
@jwt_required()
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}
        
        db = current_app.config['DB']
        
        # Get user info
        user = db.users.find_one({'_id': ObjectId(user_id)})
        
        # Update alert
        result = db.alerts.update_one(
            {'_id': ObjectId(alert_id)},
            {
                '$set': {
                    'status': 'acknowledged',
                    'acknowledged_by': user['email'],
                    'acknowledged_at': datetime.utcnow(),
                    'notes': data.get('notes', '')
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Alert not found or already acknowledged'}), 404
        
        return jsonify({'message': 'Alert acknowledged successfully'}), 200
        
    except Exception as e:
        print(f"Acknowledge alert error: {e}")
        return jsonify({'error': 'Failed to acknowledge alert'}), 500

@alerts_bp.route('/<alert_id>/resolve', methods=['POST'])
@jwt_required()
def resolve_alert(alert_id):
    """Mark an alert as resolved"""
    try:
        user_id = get_jwt_identity()
        data = request.get_json() or {}
        
        db = current_app.config['DB']
        
        # Get user info
        user = db.users.find_one({'_id': ObjectId(user_id)})
        
        # Update alert
        result = db.alerts.update_one(
            {'_id': ObjectId(alert_id)},
            {
                '$set': {
                    'status': 'resolved',
                    'resolved_by': user['email'],
                    'resolved_at': datetime.utcnow(),
                    'resolution_notes': data.get('resolution_notes', '')
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Alert not found'}), 404
        
        return jsonify({'message': 'Alert resolved successfully'}), 200
        
    except Exception as e:
        print(f"Resolve alert error: {e}")
        return jsonify({'error': 'Failed to resolve alert'}), 500

@alerts_bp.route('/summary', methods=['GET'])
@jwt_required()
def get_alerts_summary():
    """Get summary of alerts"""
    try:
        db = current_app.config['DB']
        
        # Get time range
        hours = int(request.args.get('hours', 24))
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Count by severity
        severity_pipeline = [
            {'$match': {'timestamp': {'$gte': start_time}}},
            {'$group': {'_id': '$severity', 'count': {'$sum': 1}}}
        ]
        severity_counts = list(db.alerts.aggregate(severity_pipeline))
        
        severity_summary = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for item in severity_counts:
            if item['_id'] in severity_summary:
                severity_summary[item['_id']] = item['count']
        
        # Count by status
        status_pipeline = [
            {'$match': {'timestamp': {'$gte': start_time}}},
            {'$group': {'_id': '$status', 'count': {'$sum': 1}}}
        ]
        status_counts = list(db.alerts.aggregate(status_pipeline))
        
        status_summary = {'active': 0, 'acknowledged': 0, 'resolved': 0}
        for item in status_counts:
            if item['_id'] in status_summary:
                status_summary[item['_id']] = item['count']
        
        # Recent critical alerts
        critical_alerts = list(db.alerts.find(
            {'timestamp': {'$gte': start_time}, 'severity': 'critical'},
            {'_id': 0, 'attack_type': 1, 'source_ip': 1, 'timestamp': 1}
        ).sort('timestamp', -1).limit(5))
        
        for alert in critical_alerts:
            alert['timestamp'] = alert['timestamp'].isoformat()
        
        return jsonify({
            'summary': {
                'by_severity': severity_summary,
                'by_status': status_summary,
                'total': sum(severity_summary.values()),
                'time_range': f'Last {hours} hours'
            },
            'recent_critical': critical_alerts
        }), 200
        
    except Exception as e:
        print(f"Get alerts summary error: {e}")
        return jsonify({'error': 'Failed to fetch alerts summary'}), 500

@alerts_bp.route('/trends', methods=['GET'])
@jwt_required()
def get_alert_trends():
    """Get alert trends over time"""
    try:
        db = current_app.config['DB']
        
        # Get data for last 7 days grouped by day
        start_time = datetime.utcnow() - timedelta(days=7)
        
        trends_pipeline = [
            {'$match': {'timestamp': {'$gte': start_time}}},
            {'$group': {
                '_id': {
                    'year': {'$year': '$timestamp'},
                    'month': {'$month': '$timestamp'},
                    'day': {'$dayOfMonth': '$timestamp'}
                },
                'count': {'$sum': 1},
                'high_severity': {
                    '$sum': {
                        '$cond': [
                            {'$in': ['$severity', ['high', 'critical']]},
                            1,
                            0
                        ]
                    }
                }
            }},
            {'$sort': {'_id': 1}}
        ]
        
        trends = list(db.alerts.aggregate(trends_pipeline))
        
        # Format trends
        trend_data = []
        for item in trends:
            date_obj = datetime(
                item['_id']['year'],
                item['_id']['month'],
                item['_id']['day']
            )
            trend_data.append({
                'date': date_obj.strftime('%Y-%m-%d'),
                'total_alerts': item['count'],
                'high_severity_alerts': item['high_severity']
            })
        
        return jsonify({
            'trends': trend_data,
            'period': 'Last 7 days'
        }), 200
        
    except Exception as e:
        print(f"Get alert trends error: {e}")
        return jsonify({'error': 'Failed to fetch alert trends'}), 500